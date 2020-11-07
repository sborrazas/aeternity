-module(aec_trees_proxy).

-export([ start_monitor/4 ]).
        %% , register_clients/2 ]).

%% -export([ client_tree/3 ]).

%% -export([ proxy_get/2
%%         , proxy_put/3
%%         , proxy_drop_cache/1
%%         , proxy_list_cache/1]).

-export([ proxy_init/1
        , proxy_get/4
        , proxy_put/4
        , proxy_iter/4 ]).

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

-type index() :: non_neg_integer().
-type first_access() :: boolean().

-record(st, { trees         :: undefined | aec_trees:trees()
            , env           :: aex_env:env()
            , proxy_trees   :: aec_trees:trees()
            , dontverify    :: boolean()
            , ctrees        :: #{ index() => aec_trees:trees() }
            , deps    = #{} :: #{ aeser_id:id() => [index()] }
            , claims  = #{} :: #{ index() => [aeser_id:id()] }
            , clients = []  :: #{ pid() => {index(), first_access()}, index() => pid() }
            , pending = []  :: #{ index() => [index()] }
            , valid   = []  :: [pid()]
            , invalid = []  :: [pid()]
            , events  = []  :: aetx_env:events() }).

-record(pstate, { cache :: term()
                , type  :: aec_trees:tree_type()
                , pid   :: pid() }).

-include_lib("aeutils/include/aeu_proxy.hrl").
-include_lib("mnesia/src/mnesia.hrl").

-type trees()    :: aec_trees:trees().
-type env()      :: aetx_env:env().
-type proplist() :: proplists:proplist().

-spec start_monitor(trees(), env(), [aetx_sign:tx()], proplist()) ->
          {ok, {pid(), reference()}}.
-if(?OTP_RELEASE >= 23).
start_monitor(Trees, Env, SignedTxs, Opts) ->
    gen_server:start_monitor(?MODULE, {Trees, Env, SignedTxs}, []).
-else.
start_monitor(Trees, Env, SignedTxs, Opts) ->
    _TStore = get_tstore(),
    {ok, Pid} = gen_server:start(?MODULE, {Trees, Env, SignedTxs, Opts}, []),
    MRef = monitor(process, Pid),
    {ok, {Pid, MRef}}.
-endif.

%% register_clients(Proxy, Clients) ->
%%     gen_server:cast(Proxy, {clients, Clients}).

%% -spec client_tree(type(), pid(), empty | {binary(), binary()}) -> aeu_mtrees:mtree().
%% client_tree(Type, Pid, empty) ->
%%     %% aeu_mtrees:proxy_tree(?MODULE, {Type, Pid, empty});
%%     aeu_mtrees:new_with_backend(
%%       empty,
%%       aeu_mp_trees_db:new(db_spec(Type, Pid)));
%% client_tree(Type, Pid, RootHash) ->
%%     %% aeu_mtrees:proxy_tree(?MODULE, {Type, Pid, RootHash}).
%%     aeu_mtrees:new_with_backend(
%%       {proxy, RootHash},
%%       aeu_mp_trees_db:new(db_spec(Type, Pid))).

%% db_spec(Type, Pid) ->
%%     Cache = new_cache(),
%%     #{ handle => {Type, Pid, Cache}
%%      , cache  => Cache
%%      , get    => {?MODULE, proxy_get}
%%      , put    => {?MODULE, proxy_put}
%%      , drop_cache => {?MODULE, proxy_drop_cache}
%%      , list_cache => {?MODULE, proxy_list_cache}
%%      }.

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

init({Trees, Env, SignedTxs, Opts}) ->
    ProxyTrees = aec_trees:proxy_trees(self()),
    DontVerify = proplists:get_value(dont_verify_signature, Opts, false),
    Events = aetx_env:events(Env),
    S0 = #st{ clients     = []
            , proxy_trees = ProxyTrees
            , dontverify  = DontVerify
            , env         = Env
            , trees       = Trees
            , events      = Events },
    S = start_workers(SignedTxs, Env, ProxyTrees, DontVerify, S0),
    {ok, S#st{ clients = []
            , trees   = Trees
            , events  = Events }}.

handle_call({?MODULE, Req}, {Pid, _}, #st{} = St) ->
    handle_req(Req, Pid, St);
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

start_workers(SignedTxs, Env, ProxyTrees, DontVerify, S0) ->
    {L, S} = lists:mapfoldl(
               fun(SignedTx, {N, Sx}) ->
                       { {N, SignedTx},
                         {N+1, log_initial_deps(SignedTx, N, Sx)} }
               end, {1, S0}, SignedTxs),
    PidMap = lists:foldl(
               fun({N, STx}, M) ->
                       start_worker(N, STx, ProxyTrees, Env, DontVerify, M)
               end, #{}, L),
    S#st{clients = PidMap}.

start_worker(N, SignedTx, Trees, Env, DontVerify, PidMap) ->
    {Pid, MRef} = spawn_monitor(
                     fun() ->
                             apply_one_tx(SignedTx, Trees, Env, DontVerify)
                     end),
    PidMap#{N => {Pid, MRef, SignedTx}, Pid => {N, true}}.

restart_worker(Ix, Pid, #st{ clients     = Cs0
                           , env         = Env
                           , proxy_trees = ProxyTrees
                           , dontverify  = DontVerify } = S) ->
    lager:debug("Restarting worker ~p (~p)", [Ix, Pid]),
    {_, MRef, SignedTx} = maps:get(Ix, Cs0),
    erlang:demonitor(MRef),
    exit(Pid, kill),
    Cs = start_worker(Ix, SignedTx, Env, ProxyTrees, DontVerify, maps:remove(Pid, Cs0)),
    S#st{clients = Cs}.


log_initial_deps(SignedTx, N, #st{ deps   = Deps0
                                 , claims = Claims0 } = S) ->
    {Mod, Tx} = aetx:specialize_callback(aetx_sign:tx(SignedTx)),
    Ids = Mod:entities(Tx),
    Deps =
        lists:foldl(
          fun(Id, Depsx) ->
                  Type = id_to_type(Id),
                  maps:update_with({Type, Id}, fun(L) ->
                                                       ordsets:add_element(N, L)
                                               end, [], Depsx)
          end, Deps0, Ids),
    Claims = Claims0#{ N => Ids },
    S#st{ deps = Deps, claims = Claims }.

%% We map dependencies keyed on {Type, Id} where Id is whatever it is the client
%% looks up. In the case of txs, the entities are proper ids, but we can't necessarily
%% derive a proper id from the lookup key used for accessing a tree.
id_to_type(Id) ->
    {Tag, _} = aeser_id:specialize(Id),
    case Tag of
        account    -> accounts;
        name       -> ns;
        commitment -> ns;
        oracle     -> oracles;
        contract   -> contracts;
        channel    -> channels
    end.
             

apply_one_tx(SignedTx, Trees, Env, DontVerify) ->
    try aec_trees:apply_one_tx(SignedTx, Trees, Env, DontVerify) of
        {ok, _Trees1, Env1} ->
            exit({ok, aetx_env:events(Env1)});
        {error, _} = Err ->
            exit(Err)
    catch
        Type:What:ST ->
            lager:debug("CAUGHT: ~p:~p / ~p", [Type, What, ST]),
            exit({Type, What})
    end.

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
            {Res, Trees1} = handle_req(Req, Pid, Trees),
            gen_server:reply(Ref, Res),
            St#st{pending = lists:keydelete(Pid, 1, Pend), trees =  Trees1}
    end.

handle_req({aeu_mtrees, get, F, Type, Args} = Req, {Pid,Ref}, #st{deps = Deps} = St) ->
    case check_deps(Type, Key, Pid, St) of
        {reply, _, _} = Reply ->
            Reply;
        {ok, St1} ->
            Res = try_req(fun() ->
                                  aeu_mtrees:lookup(Key, aec_trees:get_mtree(Type, Trees))
                          end),
            {reply, Res, St1};
        {wait, St1} ->
            {noreply, add_pending(Pid, Ref, Req, St1)};
        {error, _} = Err ->
            {reply, {'$fail', Err}, st}
    end.

add_pending(Pid, Ref, Req, #st{pending = Pend} = St) ->
    St#st{pending = [{Pid, Ref, Req} | Pend]}.

deps_ids(root_hash, _, Type, _Trees) ->
    [{Type, root_hash}];
deps_ids(delete, {Key}, Type, _Trees) ->
    [{Type, Key}];
deps_ids(get, {Key}, Type, _Trees) ->
    [{Type, Key}];
deps_ids(lookup, {Key}, Type, _Trees) ->
    [{Type, Key}];
deps_ids(enter, {Key, _}, Type, _Trees) ->
    [{Type, Key}];
deps_ids(insert, {Key, _}, Type, _Trees) ->
    [{Type, Key}];
deps_ids(read_only_subtree, {Key}, Type, Trees) ->
    %% Is there any way we can answer this without actually returning the tree?
    Tree = aec_trees:get_mtree(Type, Trees),
    case aeu_mtrees:read_only_subtree(Key, Tree) of
        {ok, Subtree} ->
            {[ {Type, K} || {leaf, K} <- aeu_mtrees:unfold(Subtree) ], Subtree};
        {error, _} ->
            []
    end.

check_deps(Type, F, Args, Pid, #st{trees = Trees} = St) ->
    case deps_ids(F, Args, Type, Trees) of
        {Ids, CachedResult} ->
            %% e.g. for read_only_subtree
            case check_deps_ids(Ids, Pid, St) of
                {ok, St1} ->
                    {reply, CachedResult, St1};
                Other ->
                    Other
            end;
        Ids when is_list(Ids) ->
            check_deps_ids(Ids, St)
    end.

check_deps_ids([], Pid, St) ->
    {ok, St};
check_deps_ids([Id|Ids], Pid, St) ->
    case check_deps(Id, St) of
        {ok, St1} ->
            check_deps_ids(Ids, St1);
        {wait, _} = Wait ->
            Wait;
        {restart, _} = Restart ->
            Restart;
        {error, _} = Error ->
            Error
    end.

check_deps(Id, Pid, #st{ clients = Cs
                       , claims  = Claims } = S) ->
    case maps:find(Pid, Cs) of
        {ok, {Ix, FirstAccess}} ->
            Id = {Type, Key},
            case maps:find(Id, Claims) of
                {ok, [Ix|_]} ->
                    %% Worker is at the head of the queue. Go!
                    %% This can happen when we have a 'pre-claim' (i.e. the entity
                    %% was apparent from the tx)
                    {ok, S#st{ clients = Cs#{Pid => {Ix, false}}}};
                {ok, [HdIx|Tl] = Refs} when HdIx < Ix ->
                    %% We must wait. If we have already accessed trees, there is a potential
                    %% for inconsistency, so we restart
                    S1 = S#st{clients = Cs#{Pid => {Ix, false}}},
                    case FirstAccess of
                        true ->
                            case ordsets:is_element(Ix, Tl) of
                                false ->
                                    Refs1 = ordsets:add_element(Ix, Refs),
                                    {wait, S#st{claims = Claims#{Id => Refs1}}};
                                true ->
                                    {wait, S1}
                            end;
                        false ->
                            %% We have identified a dependency, but have already started
                            %% accessing the state trees. 
                            {noreply, restart_worker(Ix, Pid, S)}
                    end
            end;
        error ->
            {error, unknown_pid}
    end.

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

%% Proxy callbacks

proxy_init(#{ type := Type
            , pid  := Pid }) ->
    #proxy_mp_tree{ mod = ?MODULE
                  , state = #pstate{ cache = new_cache()
                                   , type  = Type
                                   , pid   = Pid } }.

proxy_get(Mod, F, Args, P) ->
    call(Mod, get, F, Args, P).

proxy_put(Mod, F, Args, P) ->
    call(Mod, put, F, Args, P).

proxy_iter(_Mod, _F, _Args, _I) ->
    error(nyi).

call(Mod, Op, F, Args, #proxy_mp_tree{state = #pstate{ pid  = Proxy
                                                     , type = Type}}) ->
    case gen_server:call(Proxy, {?MODULE, {Mod, Op, F, Type, Args}}) of
        {'$fail', Error} ->
            error(Error);
        Reply ->
            Reply
    end.

