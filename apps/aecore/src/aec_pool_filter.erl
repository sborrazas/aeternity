-module(aec_pool_filter).

-behaviour(gen_server).

-export([start_link/0]).

-export([ list/0
        , is_blocked/1
        , new/1
        , add/2
        , remove/1
        , id/1 ]).

-export([ check/0
        , set_interval/1 ]).

-export([maybe_bootstrap/0]).

-export([ serialize_for_client/1
        , list_for_client/0 ]).


%% gen_server callbacks
-export([ init/1
        , handle_call/3
        , handle_cast/2
        , handle_info/2
        , terminate/2
        , code_change/3 ]).

-export_type([ entry/0 ]).

-record(entry, { id             :: aeser_id:id()
               , comment = <<>> :: binary() }).

-define(INTERVAL, 30000).

-record(st, { tref = start_timer(?INTERVAL)
            , interval = ?INTERVAL :: non_neg_integer() | infinity
            , file
            , file_hash }).

-opaque entry() :: #entry{}.

list() ->
    aec_db:pool_filter_list().

list_for_client() ->
    [serialize_for_client(E) || E <- list()].

is_blocked(Id) ->
    maybe_bootstrap(),
    if_id(
      Id, fun(I) ->
                  try aec_db:ensure_activity(
                        ets, fun() ->
                                     aec_db:pool_filter_lookup(I)
                             end) of
                      none ->
                          false;
                      #entry{} ->
                          true
                  catch
                      error:_ ->
                          false;
                      exit:_ ->
                          false
                  end
          end).

new(List) ->
    case lists:all(fun({I, Cmt}) ->
                           aeser_id:is_id(I)
                               andalso is_binary(Cmt);
                      (_) ->
                           false
                   end, List) of
        true ->
            aec_db:ensure_transaction(
              fun() ->
                      aec_db:pool_filter_clear(),
                      [add(Id, Cmt) || {Id, Cmt} <- List],
                      ok
              end);
        false ->
            {error, invalid}
    end.

add(Id, Comment) when is_binary(Comment) ->
    if_id(
      Id, fun(I) ->
                  aec_db:ensure_transaction(
                    fun() ->
                            aec_db:pool_filter_add(I, #entry{ id = I
                                                           , comment = Comment})
                    end)
          end).

add_entries(Entries) ->
    lists:foreach(
      fun(#entry{id = I} = E) ->
              aec_db:pool_filter_add(I, E)
      end, Entries).

remove_entries(Entries) ->
    lists:foreach(
      fun(#entry{id = I}) ->
              aec_db:pool_filter_remove(I)
      end, Entries).

remove(Id) ->
    if_id(
      Id, fun(I) ->
                  aec_db:ensure_transaction(
                    fun() ->
                            aec_db:pool_filter_remove(I)
                    end)
          end).

check() ->
    gen_server:call(?MODULE, check).

set_interval(I) when is_integer(I), I > 0; I == infinity ->
    gen_server:call(?MODULE, {set_interval, I}).


id(Id) ->
    if_id(Id, fun(I) ->
                      I
              end).

if_id(Id, F) ->
    if_id(Id, F, {error, not_an_id}).

if_id(Id, F, Other) when is_function(F, 1) ->
    case aeser_id:is_id(Id) of
        true ->
            F(Id);
        false ->
            case try_make_id(Id) of
                {ok, I} -> F(I);
                error ->
                    Other
            end
    end.

try_make_id(<<"ak_", _/binary>> = AK) ->
    case aeser_api_encoder:decode(AK) of
        {account_pubkey, PK} ->
            {ok, aeser_id:create(account, PK)};
        _ ->
            error
    end.

-spec serialize_for_client(entry()) -> map().
serialize_for_client(#entry{ id = Id
                           , comment = Comment }) ->
    #{ <<"id">>      => aeser_api_encoder:encode(id_hash, Id)
     , <<"comment">> => Comment }.

maybe_bootstrap() ->
    case whereis(?MODULE) of
        undefined ->
            spawn(fun() ->
                          register(pool_filter_bootstrapper, self()),  %% intended to crash if conflict
                          bootstrap()
                  end);
        _ ->
            ok
    end.

bootstrap() ->
    aec_db:check_table(aec_pool_filter),
    case aecore_sup:child_spec(?MODULE) of
        undefined ->
            {error, no_child_spec};
        Spec ->
            supervisor:start_child(aecore_sup, Spec)
    end.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    {ok, #st{}}.

handle_call({set_interval, I}, _From, St) ->
    if is_integer(I), I > 0 ->
            {reply, ok, restart_timer(St#st{interval = I})};
       I == infinity ->
            {reply, ok, restart_timer(St#st{interval = infinity})}
    end;
handle_call(check, _From, St) ->
    {reply, ok, check_file(St)};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_request}, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({timeout, TRef, {?MODULE, check}}, #st{tref = TRef} = St) ->
    St1 = check_file(St),
    {noreply, restart_timer(St1#st{tref = undefined})};
handle_info(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, _St) ->
    ok.

code_change(_FromVsn, St, _Extra) ->
    {ok, St}.

restart_timer(#st{interval = I} = St) ->
    case St#st.tref of
        undefined -> ok;
        TRef ->
            erlang:cancel_timer(TRef)
    end,
    St#st{tref = start_timer(I)}.

start_timer(infinity) ->
    undefined;
start_timer(I) ->
    erlang:start_timer(I, self(), {?MODULE, check}).

check_file(#st{file_hash = FHash } = St) ->
    {F, St1} = get_filename(St),
    case read_file(F) of
        {ok, Bin} ->
            case new_file_hash(Bin, St1) of
                {true, St2} ->
                    parse_permissions(Bin, St2);
                false ->
                    St1
            end;
        {error, enoent} ->
            St1
    end.

read_file(F) ->
    file:read_file(F).

get_filename(#st{file = undefined} = St) ->
    F = filename:join(setup:data_dir(), "pool_filter.txt"),
    {F, St#st{file = F}};
get_filename(#st{file = F} = St) ->
    {F, St}.

new_file_hash(Bin, #st{file_hash = PrevHash} = St) ->
    case aec_hash:sha256_hash(Bin) of
        PrevHash ->
            false;
        NewHash ->
            {true, St#st{file_hash = NewHash}}
    end.

parse_permissions(Bin, St) ->
    Entries = lists:foldr(fun split_line/2, [], lines(Bin)),
    aec_db:ensure_transaction(
      fun() ->
              Existing = list(),
              add_entries(Entries),
              remove_entries([E || #entry{id = Id} = E <- Existing,
                                   not lists:keymember(Id, #entry.id, Entries)])
      end),
    St.

lines(Bin) when is_binary(Bin) ->
    [L || L <- re:split(Bin, <<"\n">>, [{return,binary}]),
          L =/= <<>>].

split_line(L, Acc) when is_binary(L) ->
    case re:split(L, <<"[\s]+">>, [{return, binary}]) of
        [Key]      -> if_id(Key, fun(I) -> [#entry{id = I}|Acc]
                                 end, Acc);
        [Key, Cmt] -> if_id(Key, fun(I) -> [#entry{id = I, comment = Cmt}|Acc]
                                 end, Acc);
        _ ->
            Acc
    end.
