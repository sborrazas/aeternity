-module(aec_pool_filter).

-export([ list/0
        , is_blocked/1
        , new/1
        , add/2
        , remove/1
        , id/1 ]).

-export([bootstrap/0]).

-export([ serialize_for_client/1 ]).

-export_type([ entry/0 ]).

-record(entry, { id             :: aeser_id:id()
               , comment = <<>> :: binary() }).

-opaque entry() :: #entry{}.

list() ->
    aec_db:pool_filter_list().

is_blocked(Id) ->
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

remove(Id) ->
    if_id(
      Id, fun(I) ->
                  aec_db:ensure_transaction(
                    fun() ->
                            aec_db:pool_filter_remove(I)
                    end)
          end).
id(Id) ->
    if_id(Id, fun(I) ->
                      I
              end).


if_id(Id, F) when is_function(F, 1) ->
    case aeser_id:is_id(Id) of
        true ->
            F(Id);
        false ->
            case try_make_id(Id) of
                {ok, I} -> F(I);
                error ->
                    {error, not_an_id}
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


bootstrap() ->
    aec_db:check_table(aec_pool_filter).
