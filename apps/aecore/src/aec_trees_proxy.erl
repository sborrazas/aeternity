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

-record(tree, { handle :: any()
              , proxy  :: pid()
              , cache  :: ets:table() }).

-spec start_monitor(aec_trees:trees(), aetx_env:events()) -> {ok, {pid(), reference()}}.
-if(?OTP_RELEASE >= 23).
start_monitor(Trees, Events) ->
    gen_server:start_monitor(?MODULE, {Trees, Events}, []).
-else.
start_monitor(Trees, Events) ->
    {ok, Pid} = gen_server:start(?MODULE, {Trees, Events}, []),
    MRef = monitor(process, Pid),
    {ok, {Pid, MRef}}.
-endif.

register_clients(Proxy, Clients) ->
    gen_server:cast(Proxy, {clients, Clients}).

-spec client_tree(type(), pid(), {binary(), binary()}) -> aec_trees:trees().
client_tree(Type, Pid, {RootHash, _} = Root) ->
    aeu_mtrees:new_with_backend(
      RootHash,
      aeu_mp_trees_db:new(db_spec(Type, Pid, Root))).

db_spec(Type, Pid, {RootHash, Value}) ->
    #{ handle => {Type, Pid}
     , cache  => new_cache(RootHash, Value)
     , get    => {?MODULE, proxy_get}
     , put    => {?MODULE, proxy_put}
     , drop_cache => {?MODULE, proxy_drop_cache}
     , list_cache => {?MODULE, proxy_list_cache}
     }.

proxy_put(Key, Value, #tree{cache = Cache} = Tree) ->
    ets:insert(Cache, {Key, write, {value, Value}}),
    Tree.

proxy_get(Key, #tree{handle = Handle, cache = Cache, proxy = P}) ->
    case ets:lookup(Cache, Key) of
        [{_, _, Res}] -> Res;
        [] ->
            Res = gen_server:call(P, {?MODULE, get, Handle, Key}),
            ets:insert(Cache, {Key, read, Res}),
            Res
    end.

proxy_enter(Key, Val, #tree{cache = Cache} = T) ->
    ets:insert(Cache, {Key, write, {value, Val}}),
    T.

proxy_delete(Key, #tree{cache = Cache} = T) ->
    ets:insert(Cache, {Key, delete, none}),
    T.

proxy_drop_cache(#tree{cache = Cache} = T) ->
    [{RootHash, _, Value}] = ets:lookup(Cache, root_hash),
    ets:delete(Cache),
    T#tree{ cache = new_cache(RootHash, Value) }.

proxy_list_cache(#tree{ cache = Cache }) ->
    ets:select(Cache, [ {{'$1', write, {value, '$2'}}, [], [{{'$1', '$2'}}]} ]).

new_cache(RootHash, Value) ->
    T = ets:new(proxy_cache, [ordered_set]),
    ets:insert(T, {root_hash, read, {value, Value}}),
    ets:insert(T, {RootHash, read, {value, Value}}),
    T.

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
                   fun({Type, Key, Value}, Ts) ->
                           int_put(Type, Key, Value, Ts)
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
    {int_get(Type, Key, Trees), Trees};
handle_req({?MODULE, put, Type, Key, Value}, Trees) ->
    %% TODO: is this right?
    {ok, int_put(Type, Key, Value, Trees)}.

int_get(Type, Key, Trees) ->
    Tree = aec_trees:get_tree(Type, Trees),
    aec_db:ensure_activity(
      async_dirty, fun() ->
                           aeu_mtrees:get(Key, Tree)
                   end).

int_put(Type, Key, Value, Trees) ->
    Tree = aec_trees:get_tree(Type, Trees),
    Tree1 = aec_db:ensure_activity(
              async_dirty, fun() -> aeu_mtrees:enter(Key, Value, Tree) end),
    {ok, aec_trees:set_tree(Type, Tree1, Trees)}.

     
