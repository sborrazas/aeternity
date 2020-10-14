-module(aec_trees_proxy).

-export([ start_monitor/2
        , register_clients/2 ]).

-export([ client_tree/3 ]).

-export([ proxy_get/2
        , proxy_put/3
        , proxy_drop_cache/1
        , proxy_list_cache/1]).

-export([ init/1
        , handle_call/3
        , handle_cast/2
        , handle_info/2
        , terminate/2
        , code_change/3 ]).

-type type() :: channels | calls | accounts | contracts | ns.
-type key() :: term().
-type value() :: term().

-type req() :: {?MODULE, get, type(), term()}
             | {?MODULE, put, type(), key(), value()}.

-type pend() :: {pid(), {pid(), term()}, req()}.

-record(st, { trees        :: undefined | aec_trees:trees()
            , clients = [] :: [pid()]
            , pending = [] :: [pend()]
            , valid   = [] :: [pid()]
            , invalid = [] :: [pid()]
            , events  = [] :: aetx_env:events()}).

-include_lib("mnesia/src/mnesia.hrl").

-spec start_monitor(aec_trees:trees(), aetx_env:events()) -> {ok, {pid(), reference()}}.
-if(?OTP_RELEASE >= 23).
start_monitor(Trees, Events) ->
    gen_server:start_monitor(?MODULE, {Trees, Events}, []).
-else.
start_monitor(Trees, Events) ->
    _TStore = get_tstore(),
    {ok, Pid} = gen_server:start(?MODULE, {Trees, Events}, []),
    MRef = monitor(process, Pid),
    {ok, {Pid, MRef}}.
-endif.

register_clients(Proxy, Clients) ->
    gen_server:cast(Proxy, {clients, Clients}).

-spec client_tree(type(), pid(), empty | {binary(), binary()}) -> aeu_mtrees:mtree().
client_tree(Type, Pid, empty) ->
    %% aeu_mtrees:proxy_tree(?MODULE, {Type, Pid, empty});
    aeu_mtrees:new_with_backend(
      empty,
      aeu_mp_trees_db:new(db_spec(Type, Pid)));
client_tree(Type, Pid, RootHash) ->
    %% aeu_mtrees:proxy_tree(?MODULE, {Type, Pid, RootHash}).
    aeu_mtrees:new_with_backend(
      {proxy, RootHash},
      aeu_mp_trees_db:new(db_spec(Type, Pid))).

db_spec(Type, Pid) ->
    Cache = new_cache(),
    #{ handle => {Type, Pid, Cache}
     , cache  => Cache
     , get    => {?MODULE, proxy_get}
     , put    => {?MODULE, proxy_put}
     , drop_cache => {?MODULE, proxy_drop_cache}
     , list_cache => {?MODULE, proxy_list_cache}
     }.

-define(CACHE(C), {ets, _} = C).

proxy_put(Key, Value, ?CACHE(Cache)) ->
    cache_insert(Cache, {Key, write, {value, Value}}),
    Cache;
proxy_put(_Key, _Value, {_Type, _P, ?CACHE(_Cache)}) ->
    %% needed?
    error(nyi).

proxy_get(Key, ?CACHE(Cache)) ->
    case cache_lookup(Cache, Key) of
        [{_, _, Res}] ->
            Res;
        [] ->
            none
    end;
proxy_get(Key, {Type, P, ?CACHE(Cache)}) ->
    Res = gen_server:call(P, {?MODULE, get, Type, Key}),
    cache_insert(Cache, {Key, read, Res}),
    Res.

proxy_drop_cache(?CACHE(Cache)) ->
    cache_clear(Cache),
    Cache.

proxy_list_cache(?CACHE(Cache)) ->
    {ets, Tab} = Cache,
    ets:select(Tab, [ {{'$1', write, {value, '$2'}}, [], [{{'$1', '$2'}}]} ]).

new_cache() ->
    {ets, ets:new(proxy_cache, [ordered_set])}.

cache_insert({ets, Tab}, Obj) ->
    ets:insert(Tab, Obj).

cache_lookup({ets, Tab}, Key) ->
    ets:lookup(Tab, Key).

cache_clear({ets, Tab}) ->
    ets:delete_all_objects(Tab).

%% ======================================================================
%% Gen_server side
%% ======================================================================

init({Trees, Events}) ->
    {ok, #st{ clients = []
            , trees   = Trees
            , events  = Events }}.

handle_call(Req, {Pid, _}, #st{ clients = [Pid | _], trees = Trees } = St) ->
    {Res, Trees1} = handle_req(Req, Trees),
    {reply, Res, St#st{trees = Trees1}};
handle_call(Req, {Pid,_} = From, #st{ pending = Pend } = St) ->
    {noreply, St#st{ pending = [{Pid, From, Req}|Pend] }}.

handle_cast({clients, Clients}, St) ->
    [monitor(process, Pid) || Pid <- Clients],
    {noreply, serve_pending(St#st{ clients = Clients })};
handle_cast(_, St) ->
    {noreply, St}.

handle_info({'DOWN', _MRef, process, Pid, Reason}, #st{ clients = [Pid | Cs]
                                                      , trees   = Trees
                                                      , events  = Events } = St) ->
    %% Current leader client is done
    {IsValid, Trees1, Events1} =
        case Reason of
            {ok, Updates, NewEvents} ->
                {true,
                 lists:foldl(
                   fun({Type, {Hash, Values}}, Ts) ->
                           apply_updates(Type, Hash, Values, Ts)
                   end, Trees, Updates),
                 Events ++ NewEvents};
            _ ->
                {false, Trees, Events}
        end,
    St1 = log_valid(IsValid, Pid, St),
    case Cs of
        [] ->
            #st{valid = Valid, invalid = Invalid} = St1,
            {stop, {ok, {Valid, Invalid, Trees1, Events1}}, St};
        _ ->
            {noreply, serve_pending(St#st{ clients = Cs
                                         , trees = Trees1
                                         , events = Events1 })}
    end;
handle_info({'DOWN', _MRef, process, Pid, _}, #st{ clients = Cs
                                                 , pending = Pend } = St) ->
    {noreply, St#st{ clients = Cs -- [Pid]
                   , pending = lists:keydelete(Pid, 1, Pend) }};
handle_info(_, St) ->
    {noreply, St}.

terminate(_Reason, _St) ->
    ok.

code_change(_FromVsn, St, _Extra) ->
    {ok, St}.

log_valid(true, Pid, #st{valid = Valid} = St) ->
    St#st{valid = [Pid | Valid]};
log_valid(false, Pid, #st{invalid = Invalid} = St) ->
    St#st{invalid = [Pid | Invalid]}.

serve_pending(#st{ clients = [Pid | _]
                 , pending = Pend
                 , trees   = Trees } = St) ->
    case lists:keyfind(Pid, 1, Pend) of
        false ->
            St;
        {_, Ref, Req} ->
            {Res, Trees1} = handle_req(Req, Trees),
            gen_server:reply(Ref, Res),
            St#st{pending = lists:keydelete(Pid, 1, Pend), trees =  Trees1}
    end.

handle_req({?MODULE, get, Type, Key}, Trees) ->
    {int_get(Type, Key, Trees), Trees}.

int_get(Type, Key, Trees) ->
    %% Note that a 'db_get' callback should return the same as
    %% aeu_mtrees:lookup/2.
    Tree = aec_trees:get_mtree(Type, Trees),
    {ok, DB} = aeu_mtrees:db(Tree),
    aec_db:ensure_activity(
      async_dirty, fun() ->
                           aeu_mp_trees_db:get(Key, DB)
                   end).

apply_updates(Type, Hash, Updates, Trees) ->
    Tree = aec_trees:get_mtree(Type, Trees),
    Tree1 = aeu_mp_trees:apply_proxy_updates(Hash, Updates, Tree),
    aec_trees:set_mtree(Type, Tree1, Trees).

%% int_put(Type, Key, Value, Trees) ->
%%     Tree = aec_trees:get_mtree(Type, Trees),
%%     Tree1 = aeu_mtrees:db_put(Key, Value, Tree),
    
%%     {ok, aec_trees:set_mtree(Type, Tree1, Trees)}.
     
get_tstore() ->
    case get(mnesia_activity_state) of
        undefined ->
            undefined;
        {_, _, non_transaction} ->
            undefined;
        {_, _, #tidstore{store = Ets}} ->
            check_store(Ets),
            {ets, Ets}
    end.

check_store(Ets) ->
    ets:tab2list(Ets).
