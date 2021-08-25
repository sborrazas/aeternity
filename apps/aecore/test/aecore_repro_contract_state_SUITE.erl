-module(aecore_repro_contract_state_SUITE).

%% common_test exports
-export(
   [
    all/0, groups/0, suite/0,
    init_per_suite/1, end_per_suite/1,
    init_per_group/2, end_per_group/2,
    init_per_testcase/2, end_per_testcase/2
   ]).

%% test case exports
-export(
   [
    start_node/1,
    mine_a_key_block/1,
    stop_node/1
   ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(MINE_RATE, 100).
-define(SPEND_FEE, 20000 * aec_test_utils:min_gas_price()).
-define(NODES, [dev1]).
-define(ACCOUNT_NONCE_LIMIT, 7).
-define(REWARD_DELAY, 2).
-define(GC_TTL, 8). %% HARDCODED IN THE CODE
-define(CACHE_SIZE, 2). %% HARDCODED IN THE CODE

-define(ALICE, {
    <<177,181,119,188,211,39,203,57,229,94,108,2,107,214, 167,74,27,
      53,222,108,6,80,196,174,81,239,171,117,158,65,91,102>>,
    <<145,69,14,254,5,22,194,68,118,57,0,134,66,96,8,20,124,253,238,
      207,230,147,95,173,161,192,86,195,165,186,115,251,177,181,119,
      188,211,39,203,57,229,94,108,2,107,214,167,74,27,53,222,108,6,
      80,196,174,81,239,171,117,158,65,91,102>>}).

all() ->
    [
     {group, all}
    ].

groups() ->
    [
     {all, [sequence],
      [{group, contract_call}
       ]},
     {contract_call, [sequence],
      [
       mine_a_key_block
      ]}
    ].

suite() ->
    [].

init_per_suite(Config) ->
    %% Do not use 'instant_mining', as it short-cuts header validation/whitelist tests
    aecore_suite_utils:init_per_suite(?NODES,
                                      #{ <<"sync">> =>
                                             #{<<"sync_allowed_height_from_top">> => 0}
                                       , <<"mempool">> =>
                                             #{ <<"tx_ttl">> => ?GC_TTL, %% default 2 weeks
                                                <<"nonce_offset">> => ?ACCOUNT_NONCE_LIMIT, %% default 5
                                                <<"cache_size">> => ?CACHE_SIZE %% default 200
                                              }
                                       , <<"mining">> =>
                                             #{ <<"expected_mine_rate">> => ?MINE_RATE,
                                                %% this is important so beneficiary can spend
                                                <<"beneficiary_reward_delay">> => ?REWARD_DELAY}},
                                      [{add_peers, true}],
                                      [{symlink_name, "latest.mempool"},
                                       {test_module, ?MODULE}]
                                      ++ Config).

end_per_suite(Config) ->
    [aecore_suite_utils:stop_node(D, Config) || D <- ?NODES],
    ok.

init_per_group(all, Config) ->
    [{nodes, [aecore_suite_utils:node_tuple(D) || D <- ?NODES]} | Config];
init_per_group(EventType, Config) when EventType =:= tx_created;
                                       EventType =:= tx_received ->
    [{push_event, EventType} | Config];
init_per_group(common_tests, Config) ->
    Config;
init_per_group(_Group, Config) ->
    start_node(Config),
    %% insert contract state
    %% insert caller account
    %% insert previous keyblock
    Config.

end_per_group(Group, _Config) when Group =:= all;
                                   Group =:= tx_created;
                                   Group =:= tx_received;
                                   Group =:= common_tests ->
    ok;
end_per_group(_Group, Config) ->
    stop_node(Config),
    ok.

init_per_testcase(_Case, Config) ->
    ct:log("testcase pid: ~p", [self()]),
    [{tc_start, os:timestamp()}|Config].

end_per_testcase(_Case, Config) ->
    Ts0 = ?config(tc_start, Config),
    ct:log("Events during TC: ~p", [[{N, aecore_suite_utils:all_events_since(N, Ts0)}
                                     || {_,N} <- ?config(nodes, Config)]]),
    ok.

%% ============================================================
%% Test cases
%% ============================================================

stop_and_check(Ns, Config) ->
    lists:foreach(
      fun(N) ->
              aecore_suite_utils:stop_node(N, Config)
      end, Ns),
    ok = aecore_suite_utils:check_for_logs(Ns, Config).

start_node(Node, Config) ->
    aecore_suite_utils:start_node(Node, Config),
    aecore_suite_utils:connect(aecore_suite_utils:node_name(Node)),
    ok = aecore_suite_utils:check_for_logs([Node], Config),
    ok.

start_node(Config) ->
    Node = dev1,
    start_node(Node, Config),
    mine_blocks_to_receive_reward(Config),
    NodeName = aecore_suite_utils:node_name(Node),
    case rpc:call(NodeName, aec_tx_pool, peek, [infinity]) of
        {ok, []} -> ok;
        {ok, Txs} ->
            TxHashes = [aeser_api_encoder:encode(tx_hash, aetx_sign:hash(STx))
                        || STx <- Txs],
            try
                aecore_suite_utils:mine_blocks_until_txs_on_chain(NodeName,
                                                                  TxHashes,
                                                                  ?GC_TTL)
            catch error:max_reached ->
                ok
            end,
            {ok, _} = aecore_suite_utils:mine_blocks(NodeName, ?GC_TTL, ?MINE_RATE, key, #{}),
            {ok, []} = rpc:call(NodeName, aec_tx_pool, peek, [infinity]),
            ok
    end,
    Alice = pubkey(?ALICE),
    SpendTx = prepare_spend_tx(Node, 
                               #{recipient_id => aeser_id:create(account, Alice),
                                 amount => ?SPEND_FEE * 100}),
    ok = rpc:call(NodeName, aec_tx_pool, push, [SpendTx, tx_created]),
    mine_tx(Node, SpendTx),
    ok.

stop_node(Config) -> stop_and_check([dev1], Config).

mine_a_key_block(_Config) ->
    Node = dev1,
    NName= aecore_suite_utils:node_name(Node),
    {ok, [Block]} = aecore_suite_utils:mine_blocks(NName, 1, ?MINE_RATE, key, #{}),
    Top = rpc:call(NName, aec_chain, top_block, [], 5000),
    ct:log("top of chain ~p: ~p (mined ~p)", [Node, Top, Block]),
    {Top, Top} = {Top, Block},
    Top.

mine_blocks_to_receive_reward(_Config) ->
    Node = dev1,
    NName= aecore_suite_utils:node_name(Node),
    {ok, _} = aecore_suite_utils:mine_blocks(NName, ?REWARD_DELAY + 1, ?MINE_RATE, key, #{}),
    ok.

prepare_spend_tx(Node, Opts) ->
    {Priv, Pub} = aecore_suite_utils:sign_keys(Node),
    prepare_spend_tx(Node, Opts, Pub, Priv).

prepare_spend_tx(Node, Opts, Pub, Priv) ->
    NodeName = aecore_suite_utils:node_name(Node),
    {ok, Nonce} = rpc:call(NodeName, aec_next_nonce, pick_for_account, [Pub]),
    Params =
        maps:merge(
            #{sender_id    => aeser_id:create(account, Pub),
              recipient_id => aeser_id:create(account, Pub),
              amount       => 1,
              fee          => ?SPEND_FEE,
              nonce        => Nonce,
              payload      => <<"">>},
            Opts),

    {ok, Tx} = aec_spend_tx:new(Params),
    aec_test_utils:sign_tx(Tx, Priv, false).

push(NodeName, SignedTx, Config) ->
    EventType = ?config(push_event, Config),
    rpc:call(NodeName, aec_tx_pool, push, [SignedTx, EventType]).

pubkey({Pubkey, _}) -> Pubkey.

mine_tx(Node, SignedTx) ->
    NodeName = aecore_suite_utils:node_name(Node),
    TxHash = aeser_api_encoder:encode(tx_hash, aetx_sign:hash(SignedTx)),
    aecore_suite_utils:mine_blocks_until_txs_on_chain(NodeName,
                                                      [TxHash],
                                                      10). %% max keyblocks
