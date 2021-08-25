%%%-------------------------------------------------------------------
%%% @copyright (C) 2017, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(aec_trees_tests).

-include_lib("eunit/include/eunit.hrl").

-include("blocks.hrl").
-include_lib("aecontract/include/aecontract.hrl").

-define(TEST_MODULE, aec_trees).
-define(MINER_PUBKEY, <<42:?MINER_PUB_BYTES/unit:8>>).

ensure_account_test_() ->
    [{"Not existing account is created with 0 balance",
      fun() ->
              Trees0 = aec_test_utils:create_state_tree(),
              AccountPubkey = <<"_________account_pubkey_________">>,

              Trees = ?TEST_MODULE:ensure_account(AccountPubkey, Trees0),

              AccountsTree = aec_trees:accounts(Trees),
              ExpectedAccount = aec_accounts:new(AccountPubkey, 0),
              ?assertEqual({value, ExpectedAccount}, aec_accounts_trees:lookup(AccountPubkey, AccountsTree))
      end},
     {"Same unmodified state tree is returned when account is present",
      fun() ->
              AccountPubkey = <<"_________account_pubkey_________">>,
              Account = aec_accounts:new(AccountPubkey, 777),
              Trees = aec_test_utils:create_state_tree_with_account(Account),

              ?assertEqual(Trees,
                           ?TEST_MODULE:ensure_account(AccountPubkey, Trees))
      end}].

signatures_check_test_() ->
    {setup,
     fun() ->
             ok = meck:new(aec_chain, [passthrough]),
             meck:expect(aec_chain, get_top_state, 0, {ok, aec_trees:new()}),
             aec_test_utils:aec_keys_setup()
     end,
     fun(TmpKeysDir) ->
             meck:unload(aec_chain),
             ok = aec_test_utils:aec_keys_cleanup(TmpKeysDir)
     end,
     [ {"Correctly signed transactions are not rejected",
        fun () ->
            SignedSpend =
                    aec_test_utils:signed_spend_tx(
                      #{recipient_id => aeser_id:create(account, <<1:32/unit:8>>),
                        amount => 1,
                        fee => 20000 * aec_test_utils:min_gas_price(),
                        nonce => 1,
                        payload => <<>>}),
            SignedTxs = [SignedSpend],
            {ok, SenderPubkey, _} = aec_test_utils:wait_for_pubkey(),
            Account = aec_accounts:new(SenderPubkey, 1000000 * aec_test_utils:min_gas_price()),
            TreesIn = aec_test_utils:create_state_tree_with_account(Account),
            Env = aetx_env:tx_env(1),
            {ok, ValidTxs, _InvalidTxs, _Trees, _Events} =
                ?TEST_MODULE:apply_txs_on_state_trees(SignedTxs, TreesIn, Env),
            ?assertEqual(SignedTxs, ValidTxs),
            ok
        end}
     , {"Transactions with broken signatures are rejected",
        fun () ->
            Tx = make_spend_tx(<<0:32/unit:8>>, <<1:32/unit:8>>),
            MalformedTxs = [aec_test_utils:sign_tx(Tx, <<0:64/unit:8>>)],
            Env = aetx_env:tx_env(1),
            {ok, ValidTxs, _InvalidTxs, _Trees, _Events} =
                ?TEST_MODULE:apply_txs_on_state_trees(MalformedTxs, aec_trees:new(), Env),
            ?assertEqual([], ValidTxs),
            ok
        end}
     ]}.

process_txs_test_() ->
    {setup,
     fun() ->
             ok = meck:new(aetx, [passthrough]),
             aec_test_utils:aec_keys_setup()
     end,
     fun(TmpKeysDir) ->
             meck:unload(aetx),
             ok = aec_test_utils:aec_keys_cleanup(TmpKeysDir)
     end,
     [ {"Transactions that causes a runtime exception are rejected",
        fun () ->
            SignedSpend =
                    aec_test_utils:signed_spend_tx(
                      #{recipient_id => aeser_id:create(account, <<1:32/unit:8>>),
                        amount => 1,
                        fee => 20000 * aec_test_utils:min_gas_price(),
                        nonce => 1,
                        payload => <<>>}),
            SignedTxs = [SignedSpend],
            {ok, SenderPubkey, _} = aec_test_utils:wait_for_pubkey(),
            Account = aec_accounts:new(SenderPubkey, 1000000 * aec_test_utils:min_gas_price()),
            TreesIn = aec_test_utils:create_state_tree_with_account(Account),
            Env = aetx_env:tx_env(1),

            meck:expect(aetx, process, fun(_, _, _) -> error(foo) end),

            {ok, ValidTxs, SignedTxs, _Trees, _Events} =
                ?TEST_MODULE:apply_txs_on_state_trees(SignedTxs, TreesIn, Env),
            ?assertEqual([], ValidTxs),
            {error, {error, foo}} =
                ?TEST_MODULE:apply_txs_on_state_trees_strict(SignedTxs, TreesIn, Env),
            ok
        end}
     ]}.

make_spend_tx(Sender, Recipient) ->
    {ok, SpendTx} = aec_spend_tx:new(#{sender_id => aeser_id:create(account, Sender),
                                       recipient_id => aeser_id:create(account, Recipient),
                                       amount => 1,
                                       fee => 20000 * aec_test_utils:min_gas_price(),
                                       nonce => 1,
                                       payload => <<>>}),
    SpendTx.

poi_test_() ->
    [ {"PoI constructed from empty state trees enables computation of state trees root hash",
       fun() ->
               Trees0 = aec_test_utils:create_state_tree(),
               Poi0 = ?TEST_MODULE:new_poi(Trees0),
               ?assertEqual(?TEST_MODULE:hash(Trees0),
                            ?TEST_MODULE:poi_hash(Poi0))
       end},
      {"PoI constructed from empty state trees can be serialized/deserialized",
       fun() ->
               Trees0 = aec_test_utils:create_state_tree(),
               Poi0 = ?TEST_MODULE:new_poi(Trees0),
               assert_equal_poi(Poi0,
                                ?TEST_MODULE:deserialize_poi(
                                   ?TEST_MODULE:serialize_poi(Poi0)))
       end},
      {"Non-empty PoI cannot be constructed from empty state trees",
       fun() ->
               AccountPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,

               Trees0 = aec_test_utils:create_state_tree(),
               Poi0 = ?TEST_MODULE:new_poi(Trees0),

               ?assertEqual({error, not_present},
                            ?TEST_MODULE:add_poi(accounts, AccountPubkey,
                                                 Trees0, Poi0)),

               ContractPubkey = aect_contracts:pubkey(make_contract(AccountPubkey)),
               ?assertEqual({error, not_present},
                            ?TEST_MODULE:add_poi(contracts, ContractPubkey,
                                                 Trees0, Poi0))
       end},
      {"Empty PoI constructed from non-empty state trees can be serialized/deserialized",
       fun() ->
               AccountPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,

               Trees0 = aec_test_utils:create_state_tree(),
               Poi0 = ?TEST_MODULE:new_poi(Trees0),

               Trees1 = ?TEST_MODULE:ensure_account(AccountPubkey, Trees0),
               Poi1 = ?TEST_MODULE:new_poi(Trees1),

               assert_equal_poi(Poi1,
                                ?TEST_MODULE:deserialize_poi(
                                   ?TEST_MODULE:serialize_poi(Poi1))),
               ?assertNotEqual(?TEST_MODULE:serialize_poi(Poi0),
                               ?TEST_MODULE:serialize_poi(Poi1))
       end},
      {"Verification of presence of object fails for PoI not including object",
       fun() ->
               AccountPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,
               Account = aec_accounts:new(AccountPubkey, 0),
               Contract = make_contract(AccountPubkey),
               ContractPubkey = aect_contracts:pubkey(Contract),

               %% Check that empty PoI does not prove object.
               Trees0 = aec_test_utils:create_state_tree(),
               Poi0 = ?TEST_MODULE:new_poi(Trees0),
               ?assertMatch({error, _},
                            aec_trees:verify_poi(accounts, AccountPubkey, Account, Poi0)),
               ?assertMatch({error, _},
                            aec_trees:verify_poi(contracts, ContractPubkey, Contract, Poi0)),

               %% Check that non-empty PoI that does not include
               %% object does not prove it.
               Trees1A = aec_trees:set_accounts(
                           Trees0,
                           aec_accounts_trees:enter(Account, aec_trees:accounts(Trees0))),
               Poi1A = ?TEST_MODULE:new_poi(Trees1A),
               {ok, Poi1A1} = ?TEST_MODULE:add_poi(accounts, AccountPubkey, Trees1A, Poi1A),
               ?assertMatch({error, _},
                            aec_trees:verify_poi(contracts, ContractPubkey, Contract, Poi1A1)),
               %%
               Trees1C = aec_trees:set_contracts(
                           Trees0,
                           aect_state_tree:insert_contract(Contract, aec_trees:contracts(Trees0))),
               Poi1C = ?TEST_MODULE:new_poi(Trees1C),
               {ok, Poi1C1} = ?TEST_MODULE:add_poi(contracts, ContractPubkey, Trees1C, Poi1C),
               ?assertMatch({error, _},
                            aec_trees:verify_poi(accounts, AccountPubkey, Account, Poi1C1)),

               ok
       end},
      {"Broken serialized PoI fails verification",
       fun() ->
               OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,
               Store    = make_store(#{<<1>> => <<"v1">>, <<2>> => <<"v2">>}),
               Contract = aect_contracts:set_state(Store, make_contract(OwnerPubkey)),
               ContractPubkey = aect_contracts:pubkey(Contract),

               Trees0 = aec_test_utils:create_state_tree(),
               Trees1 = aec_trees:set_contracts(
                          Trees0,
                          aect_state_tree:insert_contract(Contract, aec_trees:contracts(Trees0))),
               Poi1 = ?TEST_MODULE:new_poi(Trees1),
               {ok, Poi11} = ?TEST_MODULE:add_poi(contracts, ContractPubkey, Trees1, Poi1),
               Poi11Fields = aec_trees:internal_serialize_poi_fields(Poi11),

               PoiFromFieldsF =
                   fun(Fields) ->
                           aec_trees:deserialize_poi(
                             aec_trees:internal_serialize_poi_from_fields(Fields))
                   end,

               %% The identified PoI fields lead to PoI that proves object.
               ?assertEqual(ok,
                            aec_trees:verify_poi(contracts, ContractPubkey, Contract,
                                                 PoiFromFieldsF(Poi11Fields))),

               %% Check that removing a node from PoI makes object inclusion not proved.
               [{_, Poi11ProofKVs = [_,_|_]}] = %% Hardcoded expectation on test data: at least 2 nodes so able to remove 1 leaving at least a node.
                   poi_fields_get(contracts, Poi11Fields),
               lists:foreach(
                 fun(KV) ->
                         BrokenSerializedPoi =
                             PoiFromFieldsF(
                               poi_fields_update_with(
                                 contracts,
                                 fun([{H, ProofKVs = [_,_|_]}]) ->
                                         NewProofKVs = ProofKVs -- [KV],
                                         ?assertMatch(_ when length(ProofKVs) =:= (1 + length(NewProofKVs)), NewProofKVs),
                                         [{H, NewProofKVs}]
                                 end,
                                 Poi11Fields)),
                         ?assertMatch({error, _},
                                      aec_trees:verify_poi(contracts, ContractPubkey, Contract,
                                                           BrokenSerializedPoi))
                 end,
                 Poi11ProofKVs),

               ok
       end},
      {"POI for one account",
       fun() ->
               AccountKeyF = fun(A) -> aec_accounts:pubkey(A) end,
               ChangeAccountF =
                   fun(A) -> {ok, A1} = aec_accounts:earn(A, 1), A1 end,
               InsertAccountF =
                   fun(Ts, A) ->
                           As = aec_trees:accounts(Ts),
                           aec_trees:set_accounts(
                             Ts, aec_accounts_trees:enter(A, As))
                   end,

               AccountPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,
               Account = aec_accounts:new(AccountPubkey, 0),

               check_poi_for_one_object(
                 accounts,
                 AccountKeyF, ChangeAccountF,
                 InsertAccountF,
                 fun(A) -> A end,
                 Account)
       end},
      {"POI for more than one account"
      , fun() ->
                %% Carefully chosen pubkeys to provoke the intended
                %% behavior.  If not done right, the PoI will contain
                %% more accounts than we want to test ;-)
                Pubkey1 = <<1:4, 2:4, 3:4, 4:4, 123:(?MINER_PUB_BYTES-2)/unit:8>>,
                Pubkey2 = <<1:4, 2:4, 3:4, 5:4, 124:(?MINER_PUB_BYTES-2)/unit:8>>,
                Pubkey3 = <<1:4, 3:4, 4:4, 5:4, 125:(?MINER_PUB_BYTES-2)/unit:8>>,
                Pubkey4 = <<1:4, 3:4, 4:4, 6:4, 126:(?MINER_PUB_BYTES-2)/unit:8>>,

                Account1 = aec_accounts:new(Pubkey1, 0),
                Account2 = aec_accounts:new(Pubkey2, 0),
                Account3 = aec_accounts:new(Pubkey3, 0),
                Account4 = aec_accounts:new(Pubkey4, 0),

                Accounts = [Account1, Account2, Account3, Account4],
                Trees = aec_test_utils:create_state_tree_with_accounts(Accounts),

                Poi0 = ?TEST_MODULE:new_poi(Trees),

                %% Add one account at a time.
                {ok, Poi1} =
                    ?TEST_MODULE:add_poi(accounts, Pubkey1, Trees, Poi0),
                {ok, Poi2} =
                    ?TEST_MODULE:add_poi(accounts, Pubkey2, Trees, Poi1),
                {ok, Poi3} =
                    ?TEST_MODULE:add_poi(accounts, Pubkey3, Trees, Poi2),
                {ok, Poi4} =
                    ?TEST_MODULE:add_poi(accounts, Pubkey4, Trees, Poi3),

                %% Check that the reported root hash is the same in all POI.
                ?assertEqual(?TEST_MODULE:hash(Trees),
                             ?TEST_MODULE:poi_hash(Poi1)),
                ?assertEqual(?TEST_MODULE:hash(Trees),
                             ?TEST_MODULE:poi_hash(Poi2)),
                ?assertEqual(?TEST_MODULE:hash(Trees),
                             ?TEST_MODULE:poi_hash(Poi3)),
                ?assertEqual(?TEST_MODULE:hash(Trees),
                             ?TEST_MODULE:poi_hash(Poi4)),

                %% Check that the first account is present in all POI
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey1,
                                                     Account1, Poi1)),
                ?assertMatch({ok, Account1},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey1, Poi1)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey1,
                                                     Account1, Poi2)),
                ?assertMatch({ok, Account1},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey1, Poi2)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey1,
                                                     Account1, Poi3)),
                ?assertMatch({ok, Account1},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey1, Poi3)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey1,
                                                     Account1, Poi4)),
                ?assertMatch({ok, Account1},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey1, Poi4)),

                %% Check that the second account is present in all but the first
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey2,
                                                     Account2, Poi1)),
                ?assertMatch({error, not_found},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey2, Poi1)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey2,
                                                     Account2, Poi2)),
                ?assertMatch({ok, Account2},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey2, Poi2)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey2,
                                                     Account2, Poi3)),
                ?assertMatch({ok, Account2},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey2, Poi3)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey2,
                                                     Account2, Poi4)),
                ?assertMatch({ok, Account2},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey2, Poi4)),

                %% Check that the third account is present in only the last two
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey3,
                                                     Account3, Poi1)),
                ?assertMatch({error, not_found},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey3, Poi1)),
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey3,
                                                     Account3, Poi2)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey3,
                                                     Account3, Poi3)),
                ?assertMatch({ok, Account3},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey3, Poi3)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey3,
                                                     Account3, Poi4)),

                %% Check that the fourth account is present in only the last one
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey4,
                                                     Account4, Poi1)),
                ?assertMatch({error, not_found},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey4, Poi1)),
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey4,
                                                     Account4, Poi2)),
                ?assertMatch({error, not_found},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey4, Poi2)),
                ?assertMatch({error, _},
                             ?TEST_MODULE:verify_poi(accounts, Pubkey4,
                                                     Account4, Poi3)),
                ?assertMatch({error, not_found},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey4, Poi3)),
                ?assertMatch(ok,
                             ?TEST_MODULE:verify_poi(accounts, Pubkey4,
                                                     Account4, Poi4)),
                ?assertMatch({ok, Account4},
                             ?TEST_MODULE:lookup_poi(accounts, Pubkey4, Poi4)),

                %% Check serialization/deserialization of PoI
                [assert_equal_poi(PoI,
                                  ?TEST_MODULE:deserialize_poi(
                                     ?TEST_MODULE:serialize_poi(PoI)))
                 || PoI <- [Poi1, Poi2, Poi2, Poi3, Poi4]]
        end
      },
      {"PoI for one contract without store",
       fun() ->
               OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,
               Contract = make_contract(OwnerPubkey),
               ?assertEqual(make_store(#{}), aect_contracts:state(Contract)), %% Hardcoded expectation on test data.

               check_poi_for_one_contract(
                 Contract,
                 _ChangeContractF =
                     fun(C) ->
                             true = aect_contracts:active(C), %% Assumption for simplicity.
                             aect_contracts:set_active(false, C)
                     end)
       end},
      {"PoI for one contract with store",
       fun() ->
               OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,
               Contract0 = make_contract(OwnerPubkey),
               Contract1 = aect_contracts:set_state(make_store(#{<<2>> => <<"v">>}),
                                                    Contract0),

               check_poi_for_one_contract(
                 Contract1,
                 _ChangeContractF =
                     fun(C) ->
                             true = aect_contracts:active(C), %% Assumption for simplicity.
                             aect_contracts:set_active(false, C)
                     end)
       end},
      {"PoI for one contract without store that becomes with store",
       fun() ->
               OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,

               check_poi_for_one_contract(
                 make_contract(OwnerPubkey),
                 fun(C) -> %% Change contract function.
                         ?assertEqual(make_store(#{}), %% Assumption for simplicity.
                                      aect_contracts:state(C)),
                         aect_contracts:set_state(make_store(#{<<1>> => <<"v">>}), C)
                 end)
       end},
      {"PoI for one contract with store that becomes without store",
       fun() ->
               OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,

               check_poi_for_one_contract(
                 aect_contracts:set_state(make_store(#{<<1>> => <<"v">>}),
                                          make_contract(OwnerPubkey)),
                 fun(C) -> %% Change contract function.
                         ?assertEqual(#{<<1>> => <<"v">>}, %% Assumption for simplicity.
                                      from_store(aect_contracts:state(C))),
                         aect_contracts:set_state(make_store(#{}), C)
                 end)
       end},
      {"PoI for one contract with store in state trees containing multiple contracts with store",
       fun() ->
               Contracts =
                   [aect_contracts:set_state(
                      make_store(#{<<1, X>> => <<"v", X>>}), %% Distinct key per contract.
                      make_contract(<<X:?MINER_PUB_BYTES/unit:8>>))
                    || X <- [1, 2, 3]],
               [check_poi_for_a_contract_among_others(
                  C,
                  [_, _] = Contracts -- [C])
                || C <- Contracts]
       end},
      %% Empty keys are dropped silently, so this doesn't fail verification
      %% {"Serialized contract PoI with empty contract store key fails verification",
      %%  fun() ->
      %%          [check_poi_for_contract_with_invalid_store_with_binary_keys(
      %%             V, #{<<>> => <<"v">>}) || V <- vm_versions()]
      %%  end},
      {"Serialized Solidity contract PoI with invalid contract store key fails verification",
       fun() ->
               IllegalKeys =
                   [<<0, (binary:encode_unsigned(K))/binary>>
                        || K <- lists:seq(0, 3)],
               [check_poi_for_contract_with_invalid_store_with_binary_keys(
                  ?VM_AEVM_SOLIDITY_1, ?ABI_SOLIDITY_1, #{K => <<"v">>}) || K <- IllegalKeys]
       end},
      {"Serialized Sophia contract PoI with invalid contract store key fails verification",
       fun() ->
               IllegalKeys = [<<3>>, <<4, 17>>, <<16>>],
               [check_poi_for_contract_with_invalid_store_with_binary_keys(
                  ?VM_AEVM_SOPHIA_1, ?ABI_AEVM_SOPHIA_1, #{K => <<"v">>}) || K <- IllegalKeys]
       end},
      {"Serialized Sophia contract PoI with invalid contract store key fails verification",
       fun() ->
               IllegalKeys = [<<3>>, <<4, 17>>, <<16>>],
               [check_poi_for_contract_with_invalid_store_with_binary_keys(
                  ?VM_AEVM_SOPHIA_2, ?ABI_AEVM_SOPHIA_1, #{K => <<"v">>}) || K <- IllegalKeys]
       end}
    ].

assert_equal_poi(PoIExpect, PoIExpr) ->
    %% The deserialized poi contains a gb_tree, so it is operation
    %% order dependent.  The serialized version is canonical, though.
    ?assertEqual(?TEST_MODULE:serialize_poi(PoIExpect),
                 ?TEST_MODULE:serialize_poi(PoIExpr)).

assert_not_equal_poi(PoIExpect, PoIExpr) ->
    %% The deserialized poi contains a gb_tree, so it is operation
    %% order dependent.  The serialized version is canonical, though.
    ?assertNotEqual(?TEST_MODULE:serialize_poi(PoIExpect),
                    ?TEST_MODULE:serialize_poi(PoIExpr)).

check_poi_for_one_contract(Contract, ChangeContractFun) ->
    ContractKeyF = fun(C) -> aect_contracts:pubkey(C) end,
    InsertContractF =
        fun(Ts, C) ->
                Cs = aec_trees:contracts(Ts),
                aec_trees:set_contracts(
                  Ts, aect_state_tree:insert_contract(C, Cs))
        end,

    check_poi_for_one_object(
      contracts,
      ContractKeyF, ChangeContractFun,
      InsertContractF,
      fun translate_store/1,
      Contract).

check_poi_for_a_contract_among_others(Contract, OtherContracts) ->
    ContractKeyF = fun(C) -> aect_contracts:pubkey(C) end,
    InsertContractF =
        fun(Ts, C) ->
                Cs = aec_trees:contracts(Ts),
                aec_trees:set_contracts(
                  Ts, aect_state_tree:insert_contract(C, Cs))
        end,

    check_poi_for_an_object_among_others(
      contracts,
      ContractKeyF,
      InsertContractF,
      fun translate_store/1,
      Contract, OtherContracts).

check_poi_for_one_object(SubTree,
                         ObjKeyFun, ChangeObjFun,
                         InsertObjFun,
                         EqMeasure,
                         Obj) ->
    Trees0 = aec_test_utils:create_state_tree(),

    %% Add the object to the tree, and see that we can construct a POI
    %% for the correct object.
    Trees1 = InsertObjFun(Trees0, Obj),
    Poi1 = ?TEST_MODULE:new_poi(Trees1),
    ?assertEqual(?TEST_MODULE:hash(Trees1),
                 ?TEST_MODULE:poi_hash(Poi1)),
    ObjKey = ObjKeyFun(Obj),
    {ok, Poi11} = ?TEST_MODULE:add_poi(SubTree, ObjKey, Trees1, Poi1),
    ?assertEqual(?TEST_MODULE:hash(Trees1),
                 ?TEST_MODULE:poi_hash(Poi11)),

    EqMeasureOk = fun({ok, O}) -> {ok, EqMeasure(O)}; (E) -> E end,

    %% Check that the stored object in the POI is the correct one.
    ?assertEqual({ok, EqMeasure(Obj)},
                 EqMeasureOk(aec_trees:lookup_poi(SubTree, ObjKey, Poi11))),

    %% Ensure that we can verify the presence of the object in the
    %% POI.
    ?assertEqual(ok,
                 aec_trees:verify_poi(SubTree, ObjKey, Obj, Poi11)),

    %% Ensure that the POI will fail if we change the object.
    Obj1 = ChangeObjFun(Obj),
    ObjKey = ObjKeyFun(Obj1), %% Hardcoded expectation on function changing object.
    ?assertMatch({error, _},
                 aec_trees:verify_poi(SubTree, ObjKey, Obj1, Poi11)),

    ok.

check_poi_for_an_object_among_others(SubTree,
                                     ObjKeyFun,
                                     InsertObjFun,
                                     EqMeasure, %% Apply before comparing for equality (used for contracts store)
                                     Obj, OtherObjs = [_|_]) ->
    ?assertNot(lists:member(Obj, OtherObjs)), %% Hardcoded expectation on test data.

    ObjKey = ObjKeyFun(Obj),
    Trees0 = aec_test_utils:create_state_tree(),
    Trees1 = InsertObjFun(Trees0, Obj),

    %% Add all other objects to the tree.
    Trees2 =
        lists:foldl(
          fun(OthObj, TreesIn) -> InsertObjFun(TreesIn, OthObj) end,
          Trees1,
          OtherObjs),

    %% Construct a POI for the object.
    Poi2 = ?TEST_MODULE:new_poi(Trees2),
    ?assertEqual(?TEST_MODULE:hash(Trees2),
                 ?TEST_MODULE:poi_hash(Poi2)),
    {ok, Poi21} = ?TEST_MODULE:add_poi(SubTree, ObjKey, Trees2, Poi2),
    ?assertEqual(?TEST_MODULE:hash(Trees2),
                 ?TEST_MODULE:poi_hash(Poi21)),

    EqMeasureOk = fun({ok, O}) -> {ok, EqMeasure(O)}; (E) -> E end,

    %% Check that the stored object in the POI is the correct one.
    ?assertEqual({ok, EqMeasure(Obj)},
                 EqMeasureOk(aec_trees:lookup_poi(SubTree, ObjKey, Poi21))),

    %% Ensure that we can verify the presence of the object in the POI.
    ?assertEqual(ok,
                 aec_trees:verify_poi(SubTree, ObjKey, Obj, Poi21)),

    %% Enrich the POI with the other objects.
    {ok, Poi22} =
        lists:foldl(
          fun(OthObj, {ok, PoiIn}) ->
                  ?TEST_MODULE:add_poi(SubTree, ObjKeyFun(OthObj), Trees2, PoiIn)
          end,
          {ok, Poi21},
          OtherObjs),
    assert_not_equal_poi(Poi21, Poi22),
    ?assertEqual(?TEST_MODULE:hash(Trees2),
                 ?TEST_MODULE:poi_hash(Poi22)),

    %% Check that the stored object in the POI is still the correct one.
    ?assertEqual({ok, EqMeasure(Obj)},
                 EqMeasureOk(aec_trees:lookup_poi(SubTree, ObjKey, Poi22))),

    %% Ensure that we can still verify the presence of the object in the POI.
    ?assertEqual(ok,
                 aec_trees:verify_poi(SubTree, ObjKey, Obj, Poi22)),

    ok.

check_poi_for_contract_with_invalid_store_with_binary_keys(
  VmVersion, ABIVersion, InvalidStoreMap) ->
    OwnerPubkey = <<123:?MINER_PUB_BYTES/unit:8>>,

    InvalidStore = make_store(InvalidStoreMap),

    %% Generate contract invalid because of an invalid contract store key.
    ValidContract = make_contract(OwnerPubkey, VmVersion, ABIVersion),
    InvalidContract = aect_contracts:internal_set_state(InvalidStore,
                                                        ValidContract),
    ContractPubkey = aect_contracts:pubkey(InvalidContract),
    ?assertNotEqual(ValidContract, InvalidContract), %% Hardcoded expectation on test data.
    ?assertEqual(aect_contracts:pubkey(ValidContract), ContractPubkey), %% Hardcoded expectation on test data.

    %% Include invalid contract in state trees.
    Trees0 = aec_test_utils:create_state_tree(),
    InvalidTrees = aec_trees:set_contracts(
                     Trees0,
                     aect_state_tree:insert_contract(
                       InvalidContract, aec_trees:contracts(Trees0))),

    %% Generate PoI for invalid contract.
    {ok, InvalidPoi0} = ?TEST_MODULE:add_poi(
                           contracts, ContractPubkey,
                           InvalidTrees,
                           ?TEST_MODULE:new_poi(InvalidTrees)),
    InvalidSerializedPoi0 = ?TEST_MODULE:serialize_poi(InvalidPoi0),

    %% Check that PoI verification fails.
    InvalidPoi = ?TEST_MODULE:deserialize_poi(InvalidSerializedPoi0),
    assert_equal_poi(InvalidPoi0, InvalidPoi),
    ValidTrees = aec_trees:set_contracts(
                   Trees0,
                   aect_state_tree:insert_contract(
                     ValidContract, aec_trees:contracts(Trees0))),
    {ok, ValidPoi} = ?TEST_MODULE:add_poi(contracts, ContractPubkey,
                                          ValidTrees,
                                          ?TEST_MODULE:new_poi(ValidTrees)),
    assert_not_equal_poi(ValidPoi, InvalidPoi),
    ?assertEqual({error, bad_proof},
                 aec_trees:verify_poi(contracts, ContractPubkey,
                                      InvalidContract,
                                      InvalidPoi)),
    ?assertEqual({error, bad_proof},
                 aec_trees:verify_poi(contracts, ContractPubkey,
                                      ValidContract,
                                      InvalidPoi)),
    ok.

poi_fields_get(FieldKey, PoiFields) ->
    {_, FieldValue} = lists:keyfind(FieldKey, 1, PoiFields),
    FieldValue.

poi_fields_update_with(FieldKey, Fun, PoiFields) ->
    _ = poi_fields_get(FieldKey, PoiFields), %% Check valid key.
    lists:foldr(
      fun({K, V}, PoiFieldsIn) ->
              NewV = if K =:= FieldKey -> Fun(V); true -> V end,
              [{K, NewV} | PoiFieldsIn]
      end,
      [],
      PoiFields).

make_contract(Owner) ->
    make_contract(Owner, ?VM_AEVM_SOLIDITY_1, ?ABI_SOLIDITY_1).

make_contract(Owner, VmVersion, ABIVersion) ->
    {contract_create_tx, CTx} = aetx:specialize_type(ct_create_tx(Owner, VmVersion, ABIVersion)),
    aect_contracts:new(CTx).

make_store(Map) ->
    aect_contracts_store:put_map(Map, aect_contracts_store:new()).

from_store(Store) ->
    aect_contracts_store:contents(Store).

translate_store(C) ->
    Store = aect_contracts:state(C),
    aect_contracts:internal_set_state(from_store(Store), C).

ct_create_tx(Sender, VmVersion, ABIVersion) ->
    Spec =
        #{ fee         => 750000
         , owner_id    => aeser_id:create(account, Sender)
         , nonce       => 0
         , code        => <<"NOT PROPER BYTE CODE">>
         , vm_version  => VmVersion
         , abi_version => ABIVersion
         , deposit     => 10
         , amount      => 200
         , gas         => 10
         , gas_price   => 1
         , call_data   => <<"NOT ENCODED ACCORDING TO ABI">>
         , ttl         => 0
         },
    {ok, Tx} = aect_create_tx:new(Spec),
    Tx.

repro_test_() ->
    [{"Repro issue",
      fun() ->
              Trees0 = aec_test_utils:create_state_tree(),
              AccountsTree =
                  lists:foldl(
                      fun(Acc, Accum) -> aec_accounts_trees:enter(Acc, Accum) end,
                      aec_trees:accounts(Trees0),
                      [test_caller_account(), test_contract_account()] ++
                      spender_accounts()),
              ContractTree = aect_state_tree:insert_contract(test_contract(),
                                                            aec_trees:contracts(Trees0)),
              Trees1 = aec_trees:set_accounts(Trees0, AccountsTree),
              Trees = aec_trees:set_contracts(Trees1, ContractTree),
              Txs = [spend_tx1(), spend_tx2(), spend_tx3(), tx1(), tx2(),
                     tx3(), spend_tx4(), spend_tx5()],
              {ok, ValidTxs, InvalidTxs, UpdatedTrees, _Events}
                   = aec_trees:apply_txs_on_state_trees(Txs, Trees,
                                                 env(), [{strict, true},
                                                         {dont_verify_signature, true}]),
              {valid, Txs} = {valid, ValidTxs},
              {invalid, []} = {invalid, InvalidTxs},
              RootHash = aec_trees:hash(UpdatedTrees),
              <<152,128,64,142,98,190,147,168,115,200,181,43,43,
                              222,248,11,219,120,97,233,128,107,10,139,124,
                              138,252,93,119,150,241,237>> = RootHash,

              ok
      end}].

test_caller_account() ->
    {account,{id,account,
             <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
               114,202,123,16,128,162,215,23,130,121,128,190,12,181,
               253>>},
         19658346959200000000,1572,0,undefined,undefined}.

test_contract_account() ->
    {account,{id,account,
             <<79,136,57,17,91,167,60,114,88,49,255,49,243,253,76,190,
               56,108,88,137,227,138,82,113,183,227,65,60,40,140,125,
               221>>},
         0,0,1,undefined,undefined}.

test_contract() ->
    {contract,{id,contract,
              <<79,136,57,17,91,167,60,114,88,49,255,49,243,253,76,190,
                56,108,88,137,227,138,82,113,183,227,65,60,40,140,125,
                221>>},
          {id,account,
              <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                253>>},
          #{abi => 3,vm => 5},
          {code,<<249,2,135,70,3,160,122,36,51,25,181,199,234,75,
                  247,41,170,67,67,154,226,39,86,111,42,252,167,
                  209,217,199,164,103,47,205,255,101,252,21,192,
                  185,2,87,185,1,132,254,21,166,133,89,2,55,1,55,2,
                  119,119,23,40,30,0,0,0,40,30,2,2,0,45,170,130,
                  130,0,2,1,3,255,254,45,68,104,244,2,55,3,55,2,
                  119,247,39,231,0,39,55,2,119,119,39,55,2,119,119,
                  51,4,2,7,12,6,12,1,4,53,4,2,40,28,2,0,40,28,0,0,
                  2,0,52,1,4,54,5,2,2,6,3,0,1,1,4,254,62,170,100,
                  225,2,55,1,119,55,2,119,119,26,10,0,130,12,1,0,
                  44,216,0,0,95,39,12,4,0,254,100,102,153,8,2,55,2,
                  247,247,247,12,1,2,4,3,17,21,166,133,89,254,118,
                  143,133,135,2,55,0,55,0,26,10,0,132,12,3,49,85,
                  78,65,85,84,72,79,82,73,90,69,68,85,0,32,32,0,4,
                  3,17,121,168,197,107,254,121,168,197,107,2,55,2,
                  23,119,55,0,38,4,0,7,12,4,1,3,63,251,1,2,254,134,
                  166,217,158,2,55,2,247,247,247,12,1,2,4,3,17,62,
                  170,100,225,254,167,142,144,148,2,55,3,55,2,119,
                  247,39,231,0,39,23,39,23,51,4,2,7,12,6,12,1,4,53,
                  4,2,40,28,2,0,40,28,0,0,2,0,52,1,4,54,5,2,2,6,3,
                  0,1,1,4,254,174,232,104,9,0,55,1,103,119,119,23,
                  2,3,17,118,143,133,135,15,2,111,130,38,207,12,3,
                  3,50,4,0,12,3,43,17,100,102,153,8,63,2,3,17,167,
                  142,144,148,15,2,111,130,38,207,1,3,255,254,200,
                  229,249,148,0,55,1,39,119,39,55,2,119,119,2,3,17,
                  118,143,133,135,15,2,111,130,38,207,12,3,3,12,1,
                  0,12,3,43,17,134,166,217,158,63,4,3,17,45,68,104,
                  244,184,203,47,10,17,21,166,133,89,101,46,77,97,
                  112,84,101,115,116,46,115,101,116,95,109,97,112,
                  95,97,116,95,105,110,100,101,120,17,45,68,104,
                  244,61,46,77,97,112,84,101,115,116,46,102,105,
                  108,116,101,114,17,62,170,100,225,89,46,77,97,
                  112,84,101,115,116,46,103,101,116,95,109,97,112,
                  95,105,110,100,101,120,17,100,102,153,8,17,46,94,
                  53,50,17,118,143,133,135,77,46,77,97,112,84,101,
                  115,116,46,111,110,108,121,95,111,119,110,101,
                  114,17,121,168,197,107,77,46,77,97,112,84,101,
                  115,116,46,109,121,95,114,101,113,117,105,114,
                  101,17,134,166,217,158,17,46,94,53,49,17,167,142,
                  144,148,77,46,77,97,112,84,101,115,116,46,102,
                  105,108,116,101,114,95,112,117,116,17,174,232,
                  104,9,29,115,101,116,95,109,97,112,17,200,229,
                  249,148,29,103,101,116,95,109,97,112,130,47,0,
                  135,117,110,107,110,111,119,110,0>>},
          {store,#{<<1,0,0,0,0,169,98,97,116,99,104,95,101,54,57,51,
                     99,56,52,102,45,101,100,49,101,45,52,100,102,57,
                     45,98,48,50,55,45,52,101,49,53,99,55,48,55,53,
                     48,51,57>> =>
                       <<"±bQyX1IwBeMruhAUaa+LbXRT6BxbzXuwJeXmlbhJoirY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,99,100,48,99,98,54,45,
                     56,97,53,56,45,52,97,50,99,45,57,57,51,50,45,52,56,55,
                     101,54,57,102,98,97,100,49,101>> =>
                       <<"±JiY0rEFKYrwwcMPQlCj/3JrCBzlhPnKmCi5r1SKZBD0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,54,102,56,101,50,50,
                     45,100,48,53,98,45,52,51,49,101,45,98,54,99,98,45,53,98,
                     101,100,55,102,97,56,52,101,48,97>> =>
                       <<"±WENBpC09wdSWXNh9F2xa9ILcuGpGxS1r8qpJh1FpGUw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,51,55,48,53,97,101,97,45,
                     57,57,53,56,45,52,48,102,49,45,98,49,55,51,45,49,99,99,
                     49,57,52,57,49,50,53,98,102>> =>
                       <<"±Iy4DKyPlPlrO8tNnIBP0W6MgEM51BBxfTkO2hivPy80=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,102,101,48,97,50,48,
                     45,56,102,52,101,45,52,51,101,50,45,57,97,97,101,45,48,
                     48,49,53,54,55,50,53,100,49,100,54>> =>
                       <<"±F+1OOkpEkKtJ2dnCWsik98FiRnjLAIyEOYoy2KEMnz0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,48,48,50,52,57,98,49,45,
                     99,99,50,102,45,52,52,56,51,45,98,54,98,56,45,97,52,100,
                     57,97,98,56,48,53,57,101,54>> =>
                       <<"±pTuv473rqxmzFI2hjK45mRw+TIOZngGDRq+iJoyU7mU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,50,48,99,102,52,99,45,
                     50,100,48,102,45,52,97,56,97,45,98,53,57,54,45,48,57,56,
                     101,57,100,53,56,53,48,50,50>> =>
                       <<"±hEOhXdwRkQRkDnvNJUsaUkoPlorxAHtvIqXWwWDtLfo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,98,48,56,102,55,
                     49,99,45,53,48,56,53,45,52,55,56,98,45,56,98,54,100,45,
                     100,56,102,101,55,99,50,102,53,54,55,51>> =>
                       <<"±5deUpZ4m9mrlk+pGSFD4Wbjv30zTz4SEeN64ZqMUI/g=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,55,100,102,49,53,
                     55,101,45,100,50,102,102,45,52,53,97,50,45,57,51,98,51,
                     45,52,51,48,98,51,52,57,55,52,50,98,52>> =>
                       <<"±72kw3iuhaswrXiP2KrvKGQ7k2zeBxidMktH1YM8SYzQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,55,49,101,55,102,
                     97,48,45,56,56,50,98,45,52,50,97,56,45,97,51,99,49,45,
                     98,99,57,101,50,53,102,55,57,98,53,52>> =>
                       <<"±cDNqmUjMwjlagdg1jOojrXiM15zKFBqrt/jw53Vb3Ao=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,100,50,48,56,51,53,
                     98,45,54,97,98,48,45,52,56,49,57,45,56,52,49,55,45,56,
                     52,100,101,49,97,101,102,48,50,50,101>> =>
                       <<"±6vi1x0DuAxq16etDJZok2O6uhX68TTGagW+FptBckw0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,99,51,102,56,57,98,51,45,
                     48,49,97,99,45,52,51,56,97,45,57,101,55,50,45,55,56,50,
                     98,54,98,48,48,55,98,56,97>> =>
                       <<"±f6RhNinrfhixUqkjAWBZUhBptDVh3uJhM3EeOdJYqmY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,102,53,54,57,48,53,
                     45,100,53,55,52,45,52,99,56,49,45,97,54,53,55,45,55,53,
                     102,99,57,101,50,48,54,102,98,56>> =>
                       <<"±tLsfdU4kK07+RvDRRC5NKYCkMh/DKhPV0o6+6l/vWRY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,98,97,50,56,53,51,45,
                     100,99,50,98,45,52,100,50,56,45,98,51,99,50,45,49,99,55,
                     50,101,56,50,97,100,56,102,100>> =>
                       <<"±8uH7luV9ALK4QvixKFfXM4BH+e0RoHPpWR7T4qG9yOc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,52,99,52,51,97,100,98,45,
                     100,55,55,99,45,52,101,99,54,45,57,50,100,54,45,100,102,
                     57,54,51,102,51,97,53,55,102,52>> =>
                       <<"±U4E4oOuVcixcEfmWKA1ZRvjN64kh2j/IaeKm1hIlUbY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,97,51,50,100,97,100,
                     45,53,52,97,100,45,52,49,101,97,45,56,98,48,48,45,97,57,
                     52,97,55,54,48,54,54,102,101,53>> =>
                       <<"±E4c2hPPBIxNoR2CaPb+4zahQOb/tMGQ3tTRTRcnYQGc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,52,55,48,100,51,97,45,
                     97,97,50,98,45,52,54,101,102,45,97,100,55,102,45,98,48,
                     56,101,49,97,50,52,101,48,51,55>> =>
                       <<"±yQpmmC1DLhWXXJYLH/eQ5OwCjmwy3Pyqq6/+WDQIeaE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,55,53,102,49,49,99,
                     45,97,100,51,55,45,52,99,101,50,45,97,52,97,49,45,98,53,
                     98,57,51,102,97,56,52,52,56,99>> =>
                       <<"±Fj6l0E5flxeOGqs0YV1X6ePW5k33HvZvCtFG74XOPbs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,102,102,48,99,99,
                     102,45,102,55,48,48,45,52,48,49,102,45,98,99,53,101,45,
                     100,48,53,57,50,99,51,49,50,54,55,52>> =>
                       <<"±M0DEdO3Ei1u8yTd3z0b4IWEfIpz6+zfjmsQmRbgsjbA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,50,101,98,101,55,99,53,
                     45,101,100,97,50,45,52,48,52,102,45,97,102,97,55,45,49,
                     55,52,57,49,54,102,100,101,100,55,49>> =>
                       <<"±kLMXBBIwJTNiWpDY/rFywUs8Vod7T3U5hKtQ6KY1wBQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,48,99,51,100,55,54,45,
                     97,48,49,98,45,52,100,50,97,45,57,48,51,101,45,54,98,97,
                     101,50,49,54,55,51,55,52,98>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,55,51,98,102,56,49,
                     98,45,56,53,56,52,45,52,52,100,100,45,57,101,99,54,45,
                     56,52,53,55,102,101,97,98,55,97,98,49>> =>
                       <<"±ilVNhgUNHoVpKi8ASbqiTXAXMSEI0yNA90OoujwYXsA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,98,100,98,55,55,50,97,45,
                     99,101,54,56,45,52,55,51,101,45,98,101,57,56,45,56,57,
                     100,102,52,49,57,48,57,97,50,49>> =>
                       <<"±9YgE/POxeOmCPr+kRa4uxb5wQk/36yzXzuL7szTokyw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,53,100,48,99,54,97,45,
                     52,52,52,49,45,52,99,50,49,45,57,56,55,55,45,102,55,57,
                     97,51,50,97,100,52,97,53,51>> =>
                       <<"±f+xY4mFjfkyd+2AlP5IAbdtzVLU8f+h8UffJmvFkcBE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,52,49,99,57,51,100,99,45,
                     50,52,51,54,45,52,99,49,51,45,56,57,50,48,45,53,100,57,
                     57,50,101,97,97,101,57,100,54>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,98,99,56,50,52,52,98,45,
                     49,100,51,52,45,52,48,97,49,45,97,53,54,102,45,54,100,
                     99,54,97,50,48,48,55,54,56,48>> =>
                       <<"±vnnJTPhbfhUblvwrKWSq9yEC7LjNeabWbR30TnIuxQE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,56,53,49,100,97,51,45,
                     52,57,53,48,45,52,52,97,100,45,57,50,102,100,45,101,100,
                     57,53,48,54,98,53,49,98,56,52>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,100,99,51,101,100,102,
                     45,97,55,52,55,45,52,51,100,97,45,56,101,98,49,45,52,52,
                     48,56,56,97,100,57,97,98,57,54>> =>
                       <<"±P4K1ZoXh2tACTOtkH387v8sAF55T/YHa/cE8c7dI7Uc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,56,50,53,100,55,48,56,45,
                     99,55,101,55,45,52,98,97,49,45,97,55,53,48,45,100,48,48,
                     99,50,50,52,101,52,49,102,49>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,48,97,98,53,101,48,45,
                     102,54,99,49,45,52,52,97,53,45,98,49,52,101,45,100,56,
                     50,53,56,55,50,57,49,101,100,57>> =>
                       <<"±i9Jz5P2bNOZWw/7zHZyn/516K9LvalM/1gVvsVu5uAY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,98,100,98,54,102,57,
                     45,101,98,55,97,45,52,55,102,100,45,97,102,54,99,45,51,
                     97,56,51,51,49,56,52,54,49,101,100>> =>
                       <<"±rsvY6iKpXTa56xQTqLHKliiIB3uf8cKFI8+hpQ3sTY0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,98,48,99,54,48,102,53,45,
                     48,48,101,97,45,52,98,55,101,45,97,98,50,99,45,57,99,55,
                     100,56,48,97,54,48,48,102,98>> =>
                       <<"±R7pfUZxx9zxwvh5nYTMi5AczPMWOQvVdSyZ2Acvk814=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,102,100,50,97,55,54,102,
                     45,54,56,56,56,45,52,97,49,55,45,57,102,99,56,45,100,
                     101,100,55,101,54,49,52,48,53,48,50>> =>
                       <<"±5+EXiSwpiDFbKH8FLU6bbs5hP2ACMsx45sd4OKajlLc=">>, 
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,99,56,53,52,100,
                     100,97,45,100,55,56,52,45,52,57,101,48,45,98,48,101,56,
                     45,55,49,98,99,49,54,48,57,56,56,50,55>> =>
                       <<"±lJvlZ2U3xxahFIM1/m7UD+G6WOF9Il48D0jlRggCfdQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,49,100,48,101,49,100,
                     45,49,57,57,98,45,52,102,54,99,45,97,51,55,97,45,102,56,
                     54,98,50,100,57,56,49,48,55,55>> =>
                       <<"±x4iJNv5GEK80A06NR3eWWUUn1n8A0Nq6/itTDTJKYUQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,56,51,57,54,48,50,45,
                     51,53,52,48,45,52,55,54,97,45,56,49,98,49,45,102,101,97,
                     55,100,57,49,55,50,50,97,102>> =>
                       <<"±o08zcLNmBOQHkmYiSxj6Zr5Hao0KyuxHFicLo8QA24g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,57,51,54,100,48,49,45,
                     98,101,54,50,45,52,101,55,51,45,98,99,100,102,45,98,50,
                     99,97,50,51,49,55,54,49,100,55>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,100,57,98,51,56,55,45,
                     51,53,57,100,45,52,97,97,53,45,57,98,50,51,45,101,54,49,
                     56,97,98,97,54,57,102,99,51>> =>
                       <<"±4LdblDjuB3o8uU07bQt0+riY2TGYegt1vYUAfuLfK88=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,101,50,56,99,51,54,57,45,
                     99,55,50,55,45,52,52,101,54,45,57,50,97,52,45,97,98,100,
                     55,98,102,54,100,98,49,102,57>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,97,49,49,101,48,49,
                     57,45,97,54,57,49,45,52,102,48,57,45,56,97,97,100,45,48,
                     98,97,53,57,99,57,57,55,49,101,102>> =>
                       <<"±ivcIV2uI1GUK4FQ1hJp4Ud4QvqFN46LggqRI1+Eg+Og=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,56,56,101,98,55,55,45,
                     55,57,51,57,45,52,97,97,53,45,57,100,55,100,45,52,56,
                     102,55,52,55,56,51,98,56,49,99>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,49,50,97,48,49,54,45,
                     54,101,101,98,45,52,56,56,57,45,57,99,57,100,45,55,99,
                     52,98,57,54,97,56,50,97,55,56>> =>
                       <<"±OzLi2x2rmDowlGLzR2N5wFTiErvu+UOMi1RhaGUsj7w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,97,52,51,55,101,54,45,
                     53,55,48,54,45,52,57,51,97,45,57,99,50,50,45,54,50,48,
                     102,51,55,55,100,50,51,51,98>> =>
                       <<"±jU4ZJCgbj2UQfEH0exBZkOAHOFpLH3/DeF2XSU5c+II=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,51,101,97,98,101,99,
                     45,50,102,55,97,45,52,52,53,101,45,97,97,97,100,45,57,
                     101,97,101,57,99,51,52,101,56,100,102>> =>
                       <<"±YEFPURA7mgUY5xcIerbXKocqlDuMLmdzZ9ltxYquWHk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,99,101,54,55,56,52,45,
                     99,48,98,53,45,52,57,100,99,45,98,51,49,52,45,50,48,49,
                     98,97,99,56,100,55,102,50,55>> =>
                       <<"±rCjtXPZM5cFCil3DA5Q0M19XvXoSN//5hfmRmHYQn8I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,53,52,100,100,51,56,51,
                     45,48,55,97,48,45,52,53,52,50,45,57,57,53,54,45,102,48,
                     99,51,100,99,54,98,101,53,48,101>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,97,102,101,48,50,55,102,
                     45,97,56,98,98,45,52,49,100,55,45,57,49,52,54,45,48,57,
                     100,100,55,98,52,55,48,56,102,102>> =>
                       <<"±JUYzJ0a01KjYvyI3wGIzH4Rh1jACcQTDdMqmtYr4Uog=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,101,51,50,57,101,100,97,
                     45,56,53,49,52,45,52,51,56,102,45,98,101,57,98,45,55,48,
                     98,99,48,50,52,101,52,57,56,50>> =>
                       <<"±ugV0Y4diA5tNViwvEupEJBQFPf2Tpmz1FoxTGtFSXsM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,101,98,55,57,102,97,
                     45,49,57,54,97,45,52,53,97,101,45,57,53,102,49,45,56,51,
                     53,51,49,52,48,49,55,97,54,48>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,55,101,48,53,102,50,
                     45,52,98,49,57,45,52,55,48,53,45,56,57,56,55,45,102,53,
                     53,49,101,97,51,52,53,98,99,100>> =>
                       <<"±3Dgb7G4MW4Cl5qaq8FnOUE0wxhiIjXoExQujf14KuYs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,57,49,52,49,101,54,52,45,
                     53,102,48,98,45,52,48,100,97,45,98,55,100,98,45,51,52,
                     48,97,51,53,101,55,101,52,55,56>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,51,52,50,53,51,101,
                     45,51,99,52,100,45,52,97,55,53,45,98,98,52,57,45,52,98,
                     49,97,99,102,52,49,98,48,99,55>> =>
                       <<"±IUuabWa0MHDj1+1FlIztB8y2qY31g9FgTWbzzGn3N8c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,98,53,49,51,52,101,
                     45,102,55,99,54,45,52,100,51,54,45,56,53,100,52,45,51,
                     55,51,97,51,99,57,54,52,57,98,57>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,97,51,51,51,51,48,97,45,
                     102,55,102,55,45,52,101,99,48,45,57,57,57,52,45,98,98,
                     99,53,56,99,57,50,101,56,97,53>> =>
                       <<"±EhssUu2Euw5jT9Oypnvh+2vgX+sVCbhkrssMa0Q87jg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,50,52,54,98,99,55,
                     57,45,51,100,55,101,45,52,56,99,97,45,57,98,51,100,45,
                     99,55,98,56,102,52,54,53,102,98,98,55>> =>
                       <<"±EgoI7dgIHTRA+1sLPxIsWfTKxB193guoMpdtqPNA+RE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,57,101,55,57,50,
                     101,100,45,100,57,48,99,45,52,57,102,49,45,56,100,50,52,
                     45,55,101,100,100,54,51,99,49,49,57,101,102>> =>
                       <<"±MN265nbRbNr3qQEBUDqM0MDl5j/3thEQDdWZJu8ITQ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,50,53,48,53,101,50,45,
                     53,55,55,100,45,52,48,102,100,45,98,50,97,49,45,55,48,
                     54,51,102,101,53,52,101,98,53,52>> =>
                       <<"±yTB+gdmQzixDxU4Na0DN1Hfin0S7MeRhNa60sdDvfUA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,100,54,101,57,51,56,57,
                     45,57,97,50,55,45,52,100,98,53,45,97,52,51,99,45,57,55,
                     48,52,56,99,100,50,54,51,97,97>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,52,51,97,99,97,101,
                     45,55,101,52,102,45,52,54,54,56,45,98,50,55,100,45,97,
                     98,48,53,48,52,56,53,48,100,49,102>> =>
                       <<"±73jJm9ihuqbLjqc+eQilUIzzkHlciI3AxmAfSrrqzmo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,97,56,57,101,52,54,51,45,
                     101,51,55,49,45,52,57,57,48,45,56,48,50,99,45,48,53,56,
                     53,102,54,102,99,101,55,53,101>> =>
                       <<"±RTI3Uk6UiAfnobQ56u4ZKCKUBlORUcKq5PUWAj54XUM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,97,97,53,48,101,56,45,
                     49,57,50,99,45,52,48,55,53,45,98,52,55,51,45,102,101,48,
                     50,98,56,98,101,57,56,50,52>> =>
                       <<"±PHgPsPkrSfTIo/eRCssZcB/I/7JRG/BBxYYrAQebkL8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,101,97,57,99,57,55,56,45,
                     50,48,54,55,45,52,97,99,48,45,97,99,55,53,45,54,49,50,
                     48,100,54,57,53,101,102,52,53>> =>
                       <<"±3zUe2IiHmkBplRWZUoJt1KheRM8mRZnBJW46sPUHfUQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,51,57,102,55,102,97,52,
                     45,56,100,97,50,45,52,97,52,97,45,56,54,51,55,45,55,53,
                     102,49,100,49,48,56,50,49,51,57>> =>
                       <<"±DxQyPl55Iotalan+h+c2pBvMgVDuSpe5HMx0TK3esro=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,102,53,50,101,100,49,97,
                     45,53,100,97,49,45,52,97,50,52,45,97,55,49,101,45,102,
                     56,48,48,57,99,99,99,98,51,57,98>> =>
                       <<"±4L/MR+AMCMz+7/1OK9f8qTJBaZ3oTX1Er06PLpID5S8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,100,101,50,101,97,97, 
                     45,52,51,57,48,45,52,56,101,52,45,98,57,51,98,45,51,49,
                     50,100,49,55,102,57,53,102,53,54>> =>
                       <<"±EZXGpci3Disqhv1da+tJJMu2nixjMjjN7Un+0qiKpiM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,102,56,53,55,54,98,99,45,
                     50,57,49,53,45,52,56,97,49,45,56,53,50,48,45,97,51,53,
                     48,56,102,54,52,57,52,100,98>> =>
                       <<"±ggxPs2WpvhvUrkgvyUIOuMpv+sUA/cW8b+9vwmV3NaU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,57,99,102,49,49,97,45,
                     97,57,101,98,45,52,100,50,52,45,98,52,101,55,45,54,100,
                     49,51,97,53,53,52,56,55,49,102>> =>
                       <<"±4nSrI4kTS8xIZU3BNgCWt+SvPCyXeiy2LijI6isWNxs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,52,57,100,51,99,50,99,45,
                     57,101,56,52,45,52,56,52,51,45,56,56,101,48,45,52,54,
                     102,101,51,53,48,51,57,99,56,48>> =>
                       <<"±CzYj1GQurPG+mEV8RFhsV8ILnkZkmr6B6xFq0h73smI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,54,57,56,56,97,50,45,
                     100,98,98,98,45,52,49,54,49,45,97,48,49,99,45,101,97,
                     101,50,100,48,98,50,54,101,48,101>> =>
                       <<"±HU9+J9JjJw65wwfln86CYaOvLyGZHyMJUdy03ZSD678=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,54,56,51,54,99,57,50,45,
                     56,48,97,57,45,52,49,57,101,45,56,97,101,98,45,98,101,
                     49,50,56,99,53,98,53,97,100,98>> =>
                       <<"±u/PxHLW0PnACc6eNEt5V5Kfqt0HtKr8TeHpNLcgyuOw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,52,53,101,100,97,
                     98,50,45,48,54,101,49,45,52,55,51,55,45,98,51,50,56,45,
                     101,48,55,98,49,53,51,55,55,99,54,99>> =>
                       <<"±xH2l/WUX5UagwaQP5McR+IfCGuUS6VXKgiUlgno1GIo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,99,57,50,55,51,54,54,45,
                     102,100,102,100,45,52,99,49,101,45,97,53,101,97,45,97,
                     55,49,55,49,99,99,52,56,53,53,49>> =>
                       <<"±JGj4v4wk0YCZyH/2pttHu8mL9zBH12S1wUEc3UMBYnc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,98,99,54,53,48,101,49,45,
                     101,100,56,101,45,52,55,99,98,45,56,100,99,53,45,102,49,
                     99,99,56,51,54,102,52,101,49,49>> =>
                       <<"±8APkBvU/GNX7yCjzcYsm2wmqrOszrHTbkFN2fJwsGPg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,55,54,97,52,52,57,98,45,
                     98,99,97,98,45,52,48,54,97,45,97,99,48,49,45,50,53,99,
                     50,57,56,100,56,54,97,48,98>> =>
                       <<"±ps/RjPesRYTpk7Eg7nuVpnOwFIIq7OIpHGtcWnczX3A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,49,51,51,49,101,55,
                     45,51,54,102,48,45,52,53,49,49,45,57,50,98,50,45,52,102,
                     100,102,57,99,54,49,50,101,56,54>> =>
                       <<"±fcQjoz5eAglUrhGYM//3qWZgs9zzzeIqXg1bt+I07cY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,99,57,52,57,48,51,102,45,
                     101,56,49,98,45,52,100,55,97,45,97,56,57,55,45,97,100,
                     48,49,57,53,100,56,48,55,49,50>> =>
                       <<"±pab2H88FPK8JiA1m8bm/SQWuNqUDCfwkcBQtInypSds=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,55,100,54,51,55,49,
                     45,99,51,99,57,45,52,97,98,54,45,97,50,98,48,45,97,57,
                     55,97,55,101,101,49,100,100,51,55>> =>
                       <<"±sq+6LQPrdPjij4XSVRlzwwcrvfTdOxVk6ekpdXg3joc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,51,49,57,53,101,56,45,
                     98,99,52,57,45,52,52,101,48,45,97,48,57,100,45,97,102,
                     54,97,102,53,98,98,97,57,54,98>> =>
                       <<"±na0JWIbJcRpOBpx/nPbPeX1ckYlT4HGqm8TJywRmy80=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,102,52,56,100,52,
                     101,48,45,102,57,98,48,45,52,97,50,97,45,56,98,102,101,
                     45,57,50,101,98,99,97,100,100,54,49,52,99>> =>
                       <<"±kKfqTUlksw17tdJP/k/mO+sSWfc767EjAOfMetftTI4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,57,57,52,53,55,51,48,45,
                     57,99,55,54,45,52,99,53,52,45,56,54,53,97,45,56,57,98,
                     52,54,102,97,101,52,53,48,99>> =>
                       <<"±fyBxf9sl+wthcjV5k5w1DRkNYPUWpzBlhHzZgDQTWI4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,98,102,54,101,49,48,
                     45,97,56,100,50,45,52,102,50,97,45,98,52,97,48,45,101,
                     50,52,48,102,98,57,55,48,99,97,101>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,55,100,51,102,98,56,48,
                     45,49,99,99,101,45,52,97,100,101,45,56,102,53,102,45,98,
                     49,51,99,54,52,56,57,51,56,102,48>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,52,55,102,54,101,48,99,
                     45,102,52,55,49,45,52,48,54,50,45,56,56,101,102,45,54,
                     52,48,52,54,99,55,57,56,48,98,50>> =>
                       <<"±yZE5e6eLgxMelwvoPNQTnLac11FG/mOKeDJc6+43SmQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,51,98,50,98,50,49,
                     51,45,57,50,98,101,45,52,53,49,98,45,57,98,102,49,45,99,
                     52,52,100,49,53,49,48,55,55,55,53>> =>
                       <<"±AxLAV7rXmIdPapCZk+unREQ0+x1KxCSoERmYXQI9tKM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,56,49,102,55,102,97,
                     45,97,50,100,52,45,52,54,53,52,45,98,48,49,53,45,51,52,
                     56,99,51,56,55,51,53,50,53,57>> =>
                       <<"±EKTt02NWuFWZCITpyx18NTrAz3qgXSj2lPeEqBgFn9Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,54,98,97,101,97,53,45,
                     98,50,53,54,45,52,99,98,102,45,56,50,48,97,45,49,53,102,
                     54,54,56,99,99,53,98,56,101>> =>
                       <<"±mmMYFm8pNEZPtM+DAGB8fYy8QaQ3f1EU3dO89KrIwN0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,97,57,102,50,57,102,52,
                     45,99,97,53,49,45,52,101,100,49,45,56,49,55,54,45,54,
                     102,57,52,53,56,98,100,52,100,101,50>> =>
                       <<"±aTRrfKwDWdieB54ktGe45mrivxSvKCOLjCPh3M95FlA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,98,101,53,57,48,56,45,
                     98,48,102,97,45,52,50,102,98,45,98,52,97,98,45,55,100,
                     52,100,98,97,57,99,100,102,101,56>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,54,48,51,55,97,52,45,
                     100,102,98,51,45,52,49,57,57,45,57,51,51,98,45,98,57,52,
                     48,52,56,56,52,55,102,54,53>> =>
                       <<"±iPWhJZkEZ6185j5xOutRxtURr4z5gCoUQ0Ndcc6s89g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,56,56,48,57,51,99,45,
                     50,51,101,54,45,52,51,101,51,45,57,97,53,102,45,56,57,
                     50,55,49,98,98,56,52,100,55,53>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,52,55,53,55,48,49,
                     45,98,55,53,48,45,52,50,54,54,45,98,99,51,57,45,56,57,
                     53,98,54,53,48,100,50,55,102,53>> =>
                       <<"±7EfTkpEhycnK2FqjLGMswCZVxv9LVlrV+DK8vTwrjJ8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,102,99,52,54,56,98,
                     55,45,54,100,102,99,45,52,56,50,49,45,57,99,54,48,45,54,
                     56,50,48,98,48,50,98,57,53,99,102>> =>
                       <<"±KynF//+aBh0O/YMtoACk7yeshcwt9DMAmCxn4E3xqng=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,56,54,57,50,54,49,50,45,
                     100,48,57,56,45,52,101,50,53,45,57,57,49,54,45,54,49,
                     102,51,49,57,102,49,98,53,99,50>> =>
                       <<"±rPXPtNW57vT3M3W3jSznJGxcb75fw23L8fvmoWJ1e/U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,52,102,98,99,55,49,45,
                     51,57,102,49,45,52,54,102,49,45,98,57,56,57,45,99,51,52,
                     98,54,102,98,52,56,102,100,98>> =>
                       <<"±0MDSG17DynPsvmNc6iULn8SncnKf8IMl3H8CCEhJ13g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,57,51,100,98,55,49,
                     45,100,99,54,48,45,52,57,99,50,45,98,98,49,98,45,53,98,
                     57,99,102,100,48,52,53,97,57,102>> =>
                       <<"±NsiDcCUaRw2Rpi8dYu40iVN5g81+kg08tWPXfZ6M5tU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,100,102,99,53,56,
                     57,102,45,54,56,51,49,45,52,50,50,53,45,57,101,53,100,
                     45,52,99,97,56,54,100,56,98,101,57,52,102>> =>
                       <<"±wwgvTYRSVx5YDOM6D6zWQW2NSfAI7CC58WcK3eu+ZWc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,57,53,102,100,53,
                     52,52,45,50,49,99,53,45,52,100,55,56,45,97,56,54,50,45,
                     48,50,98,56,55,100,57,48,97,98,100,53>> =>
                       <<"±GtjFifRwmZ6Nx6nYQaoKEfbP0/GBLep5LXgotWq5E0Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,54,98,100,57,56,99,56,45,
                     99,48,50,53,45,52,102,48,55,45,98,48,97,102,45,101,57,
                     48,48,50,57,49,57,51,57,100,100>> =>
                       <<"±212MYBXCk1PJ6Uifyp9J4uqxLsFf1e/urjk9ySERcFg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,55,101,50,100,102,54,
                     45,56,101,53,100,45,52,50,52,48,45,98,57,56,101,45,54,
                     102,57,52,100,56,50,48,53,50,55,48>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,98,50,101,57,54,52,
                     52,45,49,51,54,57,45,52,100,49,50,45,98,102,98,57,45,51,
                     56,101,54,50,97,102,97,100,54,100,102>> =>
                       <<"±WFr8sp00ZuTJPVlsQH1TiT0ys30QbJ6HGGo/HBPb92E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,98,50,102,48,98,97,45,
                     53,48,97,49,45,52,54,56,102,45,57,99,99,54,45,100,102,
                     102,99,100,50,102,54,98,49,99,102>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,57,102,53,55,52,56,45,
                     55,57,102,57,45,52,54,51,51,45,56,99,101,55,45,56,99,98,
                     52,51,100,51,51,56,48,102,53>> => 
                       <<"±9o7VEI81fMMVoKISPIi2k8Cvc+5wMOF+YPVwYVmFqjI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,55,50,49,55,53,102,100,
                     45,48,49,49,48,45,52,55,53,99,45,97,53,100,48,45,53,49,
                     57,51,56,99,56,99,55,54,97,56>> =>
                       <<"±9CsVOtnM+D6tfIBtUYlkik0hrZEnoratcjc9qC85Imc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,53,102,56,54,102,97,
                     45,55,99,54,102,45,52,101,49,49,45,57,50,56,57,45,52,52, 
                     101,101,99,55,52,50,57,56,54,57>> =>
                       <<"±RFF3H3SFr74kzyiRf0dYe2vvUblDikHId/m6uJA7hns=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,49,56,54,49,49,56,
                     100,45,102,55,54,48,45,52,102,98,98,45,97,54,53,57,45,
                     57,102,55,56,50,101,56,102,50,98,50,55>> =>
                       <<"±q0QqnqbjwHBF/tZWzki1RXm5df03YfzqRZjA2jUjoBc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,99,54,49,48,51,100,56,
                     45,49,99,100,100,45,52,50,56,50,45,56,102,54,55,45,57,
                     48,52,51,49,55,52,53,51,53,52,54>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,48,53,55,97,98,98,45,
                     98,52,100,101,45,52,102,57,98,45,56,53,102,99,45,100,49,
                     101,48,102,97,54,50,57,49,50,100>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,51,98,98,99,57,56,57,45,
                     98,54,97,102,45,52,57,101,102,45,97,48,99,102,45,55,50,
                     98,53,99,50,101,97,50,49,98,57>> =>
                       <<"±ajH3vRNC7f5n4K0CpByvABc7BQoang3PNhZL5QBNIO8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,53,97,101,98,102,57,
                     45,100,52,55,55,45,52,100,50,52,45,56,50,52,51,45,49,
                     101,101,98,101,100,99,102,102,56,48,98>> =>
                       <<"±m9d0cTDSWHo2hyGrKdD2x13QGhqQ52qJLF3oP5HzUew=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,51,56,100,100,51,57,
                     45,53,48,100,102,45,52,53,57,101,45,57,56,55,56,45,49,
                     53,57,55,101,52,98,51,100,51,98,48>> =>
                       <<"±eN44hOoJu5k1HtFx3Pl3W2EkEvTWe1JG4/aKIFSUXak=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,55,100,55,54,51,48,45,
                     49,102,102,97,45,52,57,100,51,45,56,101,101,54,45,57,
                     102,98,48,54,51,102,51,49,97,50,102>> =>
                       <<"±P9/9E09utEA5E6vbPWD4B523imncnlNqSYH/4Z09Uyw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,52,99,99,102,50,51,100,
                     45,51,49,55,54,45,52,54,99,53,45,57,99,48,98,45,56,48,
                     97,99,100,101,50,48,54,52,50,49>> =>
                       <<"±riO9Qm53b82vP2z04zycEosg13tSor6FlcEst9xUO5A=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,97,49,53,53,55,99,
                     48,45,100,54,97,56,45,52,99,50,56,45,57,55,101,51,45,49,
                     57,54,101,54,56,49,101,99,50,57,56>> =>
                       <<"±NLMxNGFJ3kU/cAMcSPP/nROAMHBaG3X5ammH8m/hky4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,53,102,56,49,97,54,
                     45,48,54,98,99,45,52,52,97,49,45,98,55,55,51,45,97,54,
                     102,99,49,97,56,101,48,53,51,52>> =>
                       <<"±ZGHg1lWNKQ53xb6Vvc5j/8iZtpofbfE8/szrvrys3E4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,102,54,51,99,55,53,
                     45,99,51,54,48,45,52,101,52,51,45,98,53,56,53,45,100,54,
                     97,98,57,49,51,98,56,98,97,53>> =>
                       <<"±m9d0cTDSWHo2hyGrKdD2x13QGhqQ52qJLF3oP5HzUew=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,98,98,57,55,52,52,57,45,
                     51,55,55,101,45,52,97,102,53,45,97,102,49,99,45,50,101,
                     99,57,53,99,100,99,54,56,51,56>> =>
                       <<"±2Ylf9rAob7AlqCN9NAv53xuEQhIWt3wWsWu/huBrc4c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,101,49,97,54,53,56,98,
                     45,52,57,51,51,45,52,56,98,101,45,57,52,98,56,45,102,53,
                     55,54,56,51,56,57,49,49,98,53>> =>
                       <<"±3bpUmrRESqXZvZYojiS5GwlSbnATuuPjGu8vhO4Knl8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,52,51,52,57,54,50,45,
                     49,97,100,54,45,52,98,55,55,45,98,97,99,52,45,54,55,101,
                     56,50,56,51,53,48,102,51,55>> =>
                       <<"±shLYvFjgVXEB0MZ8QXMPkicZC5TZqzgoHmLShaQ+koY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,101,49,97,49,52,102,
                     45,55,97,52,53,45,52,56,54,48,45,56,54,49,50,45,102,101,
                     97,100,54,53,97,48,57,97,102,100>> =>
                       <<"±1u1/O0mDkgLPulJ2S3d/2JUfuIe7akKZ0NxiHz3yp98=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,55,100,50,56,54,53,45,
                     55,55,102,99,45,52,97,53,101,45,97,99,100,48,45,48,52,
                     99,97,99,53,55,97,100,57,98,54>> =>
                       <<"±zJf80j79KwTeqGrR0Q+I3o1J6jfOBKOkCHr8BgrqwUM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,50,50,55,97,99,101,
                     52,45,50,49,54,50,45,52,54,51,55,45,98,57,97,99,45,57,
                     55,56,56,98,101,48,57,53,97,55,97>> =>
                       <<"±TktiBb/jMPpxiuJVZlGCg3q1C0X8lYflkzh+2ooNFAU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,100,99,101,97,54,48,
                     45,50,50,53,54,45,52,98,56,49,45,56,100,52,99,45,56,50,
                     97,98,53,57,101,49,99,51,52,53>> =>
                       <<"±HrGeHixZOCp/N5nNWs/79MMUrl0r8YoUk6j1l7n/X/w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,100,49,97,53,98,50,45,
                     50,57,100,99,45,52,98,101,52,45,98,97,53,53,45,97,98,53,
                     53,55,51,100,97,100,99,56,99>> =>
                       <<"±Sv7XTYJh/biGQcBElWgcqWqEIqdms7BjeObE3ty7ykU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,54,49,48,54,57,56,45,
                     54,56,54,50,45,52,97,49,49,45,97,100,53,49,45,51,54,100,
                     54,53,102,52,49,48,55,55,102>> =>
                       <<"±ex4kchlqRgup9ABkf6ys2Ktc7ig7LaNeQYWiQeO8FRU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,97,51,55,101,48,50,45,
                     50,98,101,102,45,52,49,98,97,45,98,52,52,50,45,54,50,54,
                     51,97,52,97,53,99,48,99,53>> =>
                       <<"±EhssUu2Euw5jT9Oypnvh+2vgX+sVCbhkrssMa0Q87jg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,50,101,97,50,101,98,
                     45,48,54,55,48,45,52,100,100,98,45,57,50,97,102,45,54,
                     57,102,51,97,99,49,53,98,49,50,51>> =>
                       <<"±Fj6l0E5flxeOGqs0YV1X6ePW5k33HvZvCtFG74XOPbs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,55,49,99,102,55,49,51,
                     45,98,49,56,102,45,52,54,57,98,45,57,100,57,98,45,55,
                     101,99,56,57,48,102,51,51,54,49,102>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,56,56,99,49,101,100,99,
                     45,56,99,55,54,45,52,102,52,55,45,97,52,49,101,45,56,97,
                     50,48,97,99,98,57,56,55,100,57>> =>
                       <<"±3bpUmrRESqXZvZYojiS5GwlSbnATuuPjGu8vhO4Knl8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,56,55,102,98,49,97,
                     45,100,54,54,52,45,52,49,51,50,45,97,54,48,50,45,99,52,
                     53,97,52,102,99,49,52,50,99,49>> =>
                       <<"±Op2mLsU1scVAdUCq19Ve2aFQovn231AXpytVK+Y3jqg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,52,55,99,98,55,98,
                     57,45,54,56,98,55,45,52,48,52,55,45,57,98,57,53,45,48,
                     100,52,57,53,100,55,49,99,99,55,56>> =>
                       <<"±WSHvPBFiAADkllZ9+y4Gc/XjXTB4tPPpbsW51nV/fZI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,57,50,98,49,51,101,
                     45,55,50,101,56,45,52,99,98,54,45,98,101,48,48,45,48,
                     100,97,49,50,99,99,55,100,52,57,97>> =>
                       <<"±5MPOBXt3EqKkcY7cX5vKjwNqH/5Ow+T3QZfdF/0WHT0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,101,99,49,48,52,54,
                     51,45,57,57,102,97,45,52,99,55,98,45,97,55,54,52,45,55,
                     97,102,52,49,51,50,49,100,49,101,102>> =>
                       <<"±5bO0vAWf+8sYyolTNsC02YZ9qxIReAicTiUHU01fyqI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,50,97,51,48,97,98,
                     50,45,99,56,98,99,45,52,50,48,97,45,56,99,98,50,45,98,
                     55,98,102,52,53,54,48,56,97,101,99>> =>
                       <<"±JB1ERg3lHAd7TT1Xeizk5CqR8srq7F/pMvWDkLdA6W0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,57,55,49,49,56,53,45,
                     53,55,52,52,45,52,56,98,57,45,57,97,100,97,45,50,98,101,
                     51,51,53,48,53,49,98,54,48>> =>
                       <<"±nHrjsFzE9vUEb8pZ3nc9mAvazdgZEdscKgBEZHLg5DA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,57,55,51,55,98,56,55,45,
                     98,97,50,101,45,52,102,53,100,45,56,52,51,57,45,101,53,
                     102,97,56,98,100,102,99,53,97,57>> =>
                       <<"±qCA9pplE2eeTsZXrLFvnxTNTRReeae5mwJDqzj2xDhw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,97,53,49,97,50,102,98,45,
                     99,52,52,54,45,52,97,97,53,45,57,100,54,57,45,55,100,51,
                     49,98,50,98,102,50,97,99,102>> =>
                       <<"±toa0E7+4GWXpF4GyLwVVi1L+L/Alv6bSr47StENS13g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,52,98,57,54,101,55,57,
                     45,51,100,49,98,45,52,51,101,55,45,98,57,101,48,45,57,
                     49,53,99,54,55,97,102,54,56,57,98>> =>
                       <<"±yDIcNlVqheUz2NHAemF7L8n3G2ZHBgEbHjJCY7hqGMw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,50,101,56,101,102,
                     98,45,53,99,102,48,45,52,102,98,52,45,97,52,51,54,45,57,
                     49,49,51,98,98,48,57,99,55,102,57>> =>
                       <<"±1l1s7heuCT6aSscWxaBq/HdPvLLPfX8FERQXvFWBpkY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,100,100,99,49,97,55,56,
                     45,100,97,56,54,45,52,56,52,55,45,98,102,50,97,45,102,
                     98,49,101,98,97,49,100,53,49,49,50>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,17,97,108,97,51>> => <<21,98,97,108,97,51>>,
                   <<1,0,0,0,0,161,98,109,116,95,101,54,99,57,52,52,49,101,
                     45,48,101,56,53,45,52,101,50,51,45,56,51,54,50,45,98,
                     100,101,99,53,102,57,99,98,97,97,100>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,56,48,56,97,53,55,45,
                     50,54,99,98,45,52,49,101,54,45,97,98,48,52,45,57,99,54,
                     54,102,48,100,102,49,98,97,100>> =>
                       <<"±U4/dKPJx6zWzRLWiQvD8KVkry+8Dvma5SH5YjXT7hsI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,54,100,54,50,54,49,
                     49,45,54,97,98,52,45,52,51,100,55,45,97,99,49,101,45,56,
                     99,48,52,57,98,51,52,100,54,53,52>> =>
                       <<"±wgKjB3IMH3P920/cRbA0dbgo/uaKaKJHU7TuQeOdc/g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,99,101,100,51,98,101,
                     102,45,56,57,98,51,45,52,101,99,50,45,97,50,49,52,45,
                     101,57,99,51,54,56,101,102,99,52,98,51>> =>
                       <<"±7tWG4sO6h8Ha44l802EwHMkobJ32XWZXY/Pzh9qua64=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,100,97,52,57,50,48,
                     50,45,51,100,52,49,45,52,48,50,51,45,57,55,99,56,45,53,
                     54,102,100,51,48,97,98,57,53,101,55>> =>
                       <<"±LHSX+C4XMTOLQVgPUgjknpBSIZOis+6+Os1kAcHpoF4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,56,102,98,54,101,98,
                     45,56,99,51,99,45,52,98,97,57,45,57,98,55,99,45,48,53,
                     52,100,50,52,54,98,49,99,57,55>> =>
                       <<"±mbItTNzygRWA2L/hOu4cC4Jymu9EACusIIF0ixpyRcY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,57,55,97,97,57,54,97,45,
                     48,57,97,97,45,52,55,98,55,45,97,101,54,57,45,102,97,50,
                     98,97,52,100,54,53,51,98,101>> =>
                       <<"±XwACfTEyIYYTPCNoQ+iAbVbu8un2RJcH2WfHXDXHa7E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,50,52,57,98,97,57,45,
                     97,99,51,101,45,52,98,51,57,45,97,100,100,53,45,56,101,
                     101,55,56,52,53,49,55,55,49,48>> =>
                       <<"±B23i1bdwW8Xrn4tnT4/xMMY+bhXQtOIPCNPsEfveS+A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,57,97,57,100,48,51,45,
                     48,53,101,97,45,52,102,52,97,45,56,53,49,97,45,48,51,53,
                     54,54,53,100,102,51,55,102,52>> =>
                       <<"±5WMKQeDOXqUxHypy2wHNbqf6KiEDoJFglqVfHsN5naA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,101,51,98,56,54,99,45,
                     100,99,101,53,45,52,49,101,49,45,57,49,99,101,45,49,54,
                     55,100,55,101,54,51,49,50,56,100>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,52,50,51,57,101,102,102,
                     45,98,54,48,97,45,52,102,53,51,45,98,97,48,97,45,99,57,
                     51,102,52,49,97,101,51,52,101,97>> =>
                       <<"±3gxhMD41gJuyOrxdxSvd9pWGMSc5JGutVIPYFgKqVFI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,98,52,50,102,49,101,54,
                     45,51,102,55,99,45,52,98,100,101,45,97,53,57,100,45,57,
                     49,53,101,102,52,97,54,99,53,97,52>> =>
                       <<"±MwzVQO2LDyGFb6DAc9v6K5TukNQccwbCFirqA+WfRB8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,100,100,99,49,53,
                     57,98,45,57,55,98,101,45,52,100,101,56,45,98,50,49,101,
                     45,102,56,98,57,98,101,101,49,55,52,102,56>> =>
                       <<"±bgpey1qyFvWp6MnF+0FuzPtHTH7/Y396rSwvdXcZf0s=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,49,50,51,98,51,99,102,45,
                     52,53,101,48,45,52,51,48,100,45,97,49,99,99,45,48,49,
                     101,97,55,55,55,99,100,52,54,54>> =>
                       <<"±YkTmSxnmIXL6qH1FD+edgelwQqhKQWo6pPzZ+mJJrqI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,57,54,98,102,51,100,97,
                     45,56,57,48,57,45,52,55,54,50,45,56,102,56,51,45,56,50,
                     52,100,51,49,51,54,48,98,49,55>> =>
                       <<"±Bv0pshGNJyyupRFyv+r73JE2f+LwMzz9hwVH+udRnBE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,99,55,100,100,54,50,54,
                     45,48,54,54,52,45,52,98,53,56,45,97,99,54,57,45,98,51,
                     101,50,101,55,56,97,53,53,97,54>> =>
                       <<"±4+agBcNXfZtXEMqDAQFcsCFYj6BPVXOORt6Ev/4lWf4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,97,48,100,102,99,48,52,
                     45,50,100,51,56,45,52,97,100,50,45,56,49,51,55,45,54,98,
                     49,49,48,99,100,50,99,50,49,48>> =>
                       <<"±4g3gCHiJ//TovmEU0Nb7kkzs1frBwTYf4bROfQA/dOg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,100,57,54,52,97,53,45,
                     50,54,49,56,45,52,51,99,48,45,56,49,100,99,45,54,56,102,
                     52,101,53,102,100,98,102,48,57>> =>
                       <<"±OXPgIukyIPkhLBjQ0MVDrnwwnkZkDak6SgMU3pmfURI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,56,99,97,55,99,55,
                     54,45,98,57,55,52,45,52,50,101,53,45,56,55,99,52,45,55,
                     56,54,48,48,100,48,50,101,52,98,50>> =>
                       <<"±uajVCyvzh7m2CXgYy0W3uz0kdUXPgtP1NGjiFwYtEMA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,99,98,100,100,99,56,
                     45,49,98,50,54,45,52,51,57,57,45,98,55,102,52,45,57,54,
                     100,102,102,102,48,56,54,53,52,97>> =>
                       <<"±EoOkle7TvFuqOr05EAXrBYkpGqRToTEOziJ5SJ40kNA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,55,102,49,51,56,53,49,45,
                     98,101,48,99,45,52,51,49,48,45,56,50,97,51,45,52,102,55,
                     52,100,53,97,49,99,97,99,48>> =>
                       <<"±pT8lDfSPAi7StdQzV4O5Y9U56082HZhxdSP8y3SmMhM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,99,102,97,49,55,56,
                     49,45,97,56,55,52,45,52,55,54,55,45,56,54,56,55,45,49,
                     99,55,51,48,102,55,48,100,56,99,99>> =>
                       <<"±ZxXYOkiUUJWsRFV19bcpLqEiyqwroWslcrL0uRm39wo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,53,53,100,100,54,49,55,
                     45,98,57,52,54,45,52,54,53,102,45,56,102,49,55,45,49,54,
                     97,55,52,102,49,55,55,53,98,102>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,49,100,53,101,100,51,99,
                     45,50,54,51,102,45,52,56,55,100,45,56,100,54,55,45,102,
                     97,101,55,97,52,56,101,55,56,55,101>> =>
                       <<"±B9Nmn2ECtatH+VKfS81YcTCIlwczVcYZaJYQrYIQXKs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,56,51,54,48,99,55,100,45,
                     52,99,102,48,45,52,99,52,97,45,98,55,100,48,45,54,52,55,
                     55,54,48,99,48,56,49,56,102>> =>
                       <<"±MrwPbr7tzsR8C3oyH3axggr23VO6End4gnWHoqzSkl4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,99,49,56,53,52,99,
                     45,101,98,49,53,45,52,56,52,97,45,97,54,50,98,45,49,99,
                     55,57,48,53,48,101,97,102,52,98>> =>
                       <<"±7OEywqG54RkK7qzhBpyvaOLHzq0bRi2HPWx83DCzRiY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,52,48,97,57,52,55,
                     56,45,55,55,55,53,45,52,97,53,101,45,98,55,99,50,45,102,
                     56,48,56,97,101,100,102,101,102,102,53>> =>
                       <<"±48gejerQR8N/a8tBl+sg9XzQ5B1xXAiZScQbuq8354c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,48,55,97,98,51,52,53,45,
                     51,99,55,50,45,52,98,102,98,45,56,98,49,52,45,51,50,57,
                     99,57,99,99,99,97,51,54,56>> =>
                       <<"±qOMORG9HzJySmvLnQrx1bJiNgGM7p4UCF49mkbkTsys=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,48,102,55,97,51,53,52,45,
                     48,54,102,97,45,52,48,101,51,45,97,97,55,98,45,101,98,
                     56,100,56,100,52,98,102,53,102,52>> =>
                       <<"±FXko9pm3ydhHLo8szqD9+dhNgkKVnMU2FbWyTH0s5hc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,98,99,54,97,97,101,45,
                     52,100,51,49,45,52,98,52,57,45,98,102,57,53,45,48,54,99,
                     51,99,98,97,57,102,49,56,102>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,55,54,97,50,102,51,
                     57,45,97,52,54,51,45,52,56,101,100,45,98,52,99,48,45,
                     101,48,52,98,48,57,48,48,55,100,52,100>> =>
                       <<"±rNqGqnEuVaafGD70kN+9TUajehn+IWEqkuINPt8elCY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,52,97,49,54,98,101,55,45,
                     54,97,48,49,45,52,98,51,51,45,98,48,99,99,45,57,102,57,
                     99,101,101,102,49,100,54,50,98>> =>
                       <<"±t+ttdRu0fpTL9kWJQentuIMCuGPhKbXmYHS51QWj/44=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,98,48,101,52,102,50,97,
                     45,51,53,100,53,45,52,102,98,49,45,97,98,99,97,45,54,57,
                     97,53,48,97,53,101,101,99,102,53>> =>
                       <<"±gX/pzwtGwF+I6KQzaPd/KdfT0XW93jsRnhdfJANuBd0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,100,48,48,101,54,56,
                     45,56,101,101,57,45,52,56,49,101,45,98,101,54,50,45,53,
                     57,55,97,50,52,100,101,54,98,102,55>> =>
                       <<"±SNKv1I0/0IixsfD/8NLh63jg1Vr1BTh3bD6Zpmqohfo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,97,52,56,100,51,98,57,
                     45,98,50,102,56,45,52,54,98,56,45,97,57,98,50,45,50,51,
                     50,54,51,55,101,52,56,50,53,100>> =>
                       <<"±hZW1fBFZn3XdJOc67S/HwJ43IcqqkrYi05eDBm0llUQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,102,101,53,55,102,
                     52,56,45,50,100,97,99,45,52,53,99,57,45,57,50,100,97,45,
                     101,98,49,49,56,57,56,57,56,53,101,48>> =>
                       <<"±ry4G8tqUisP++LRxAmz9GCHU7Bpn5EuvUhF85+Vl0JE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,54,53,99,55,56,53,50,45,
                     57,97,98,56,45,52,57,49,102,45,56,57,52,52,45,98,51,99,
                     52,53,98,53,52,50,98,101,50>> =>
                       <<"±hbYnNouP3xZuZO6pt8UEBbiC6Q3ZqqSZhHw2UL5VPEE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,48,55,102,57,52,48,101,
                     45,53,99,102,49,45,52,101,101,97,45,97,54,101,99,45,53,
                     55,51,56,56,56,56,54,57,102,52,100>> =>
                       <<"±W6XPls9D34ZX4rW2bQ+O+iMgLrGtT2/t90AQ1iojzEg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,102,50,48,100,54,102,
                     45,49,100,48,48,45,52,48,102,54,45,98,50,97,50,45,49,48,
                     101,101,50,97,48,100,55,50,49,101>> =>
                       <<"±AOJVX+udOiseOqoCDqp3AOo7eLstkGSpdtEkWN8yMwU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,98,55,49,48,98,102,45,
                     102,57,97,99,45,52,56,48,97,45,98,56,99,48,45,48,54,57,
                     49,98,53,99,49,57,102,102,102>> =>
                       <<"±2gx0kKQH4ys0vwRjMihAvhLu5BftWJzOvL9fLsY8KiA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,56,51,53,56,54,98,102,45,
                     55,57,56,54,45,52,48,102,99,45,56,52,101,51,45,54,55,98,
                     97,101,48,97,51,56,100,50,97>> =>
                       <<"±YawGUYOOjtHnAk94R7UDVCGiPyBu47jtXIAkkknaFRc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,51,49,99,56,97,48,98,45,
                     48,53,102,102,45,52,101,55,102,45,98,51,54,48,45,97,98,
                     99,49,100,99,49,52,100,101,100,52>> =>
                       <<"±3uh/Bx13P1n04CIBl2WPJ23pkFfayrQAmENrRLf+2l4=">>,
                   <<1,0,0,0,0,17,107,101,121,51>> =>
                       <<25,118,97,108,117,101,51>>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,99,97,48,56,57,50,
                     98,45,100,48,101,48,45,52,100,48,54,45,56,99,51,97,45,
                     50,100,51,50,57,56,53,101,99,57,99,50>> =>
                       <<"±fSmVuBpTmGrOYKSJIX/zxygihcIOOpmCFAAtI4SpVB8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,52,52,53,51,48,102, 
                     50,45,53,99,50,51,45,52,101,53,55,45,56,102,52,52,45,98,
                     50,51,55,99,49,51,53,57,97,57,57>> =>
                       <<"±Ity+oHmMlS6upIEMRlWlGEPSkCuocUTIVXMuKimpY3A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,100,54,102,99,55,57,
                     45,48,51,51,56,45,52,97,102,53,45,98,48,50,50,45,102,53,
                     102,56,102,55,99,97,99,97,53,48>> =>
                       <<"±Ung0dLX1o2C0X6aCBonK25vrlG2KLaRNfo1qcFNk8Cc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,55,56,102,56,98,56,57,45,
                     52,50,100,101,45,52,53,57,56,45,97,102,49,99,45,98,49,
                     97,53,97,101,102,54,54,50,99,98>> =>
                       <<"±EODIucUS4MMO0IXoebwmtOL2XO5ksNbspMF1JxrI8eo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,102,55,52,49,51,
                     97,49,45,99,54,57,57,45,52,52,50,101,45,97,99,56,50,45,
                     53,100,102,100,49,54,51,51,56,51,52,100>> =>
                       <<"±NJnGEdu5JL3p40f888+Na+YvWzfq2Y63Mn7au2GCIPw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,98,98,54,48,50,49,45,
                     55,55,54,52,45,52,50,99,50,45,98,53,56,102,45,100,56,98,
                     100,97,55,50,102,99,101,55,54>> =>
                       <<"±nOaKpyBPd/MXf37JJROxR6FSV5mEwzX7If4zq1+EkaA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,100,102,50,97,97,98,55,
                     45,50,98,53,52,45,52,98,51,97,45,57,57,52,102,45,48,52,
                     98,57,100,54,54,54,102,57,54,50>> =>
                       <<"±Q95CKxCSzZo1pMO5vWLIozBPg736FTqSSHw+afXJT0c=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,55,57,57,57,53,97,
                     52,45,53,54,98,98,45,52,102,55,48,45,97,57,102,51,45,
                     102,57,98,101,57,97,49,49,49,51,100,102>> =>
                       <<"±RZ2sOpOhfUKb/2BYy017BFrXWwhENDQeoIp+NZA+6PE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,50,55,98,99,56,48,
                     55,45,101,49,52,52,45,52,99,52,49,45,57,49,102,52,45,
                     100,56,57,49,48,100,54,50,51,50,100,56>> =>
                       <<"±yF066UZmSiTTEm0IJhVPKub/23Z2d3KE0KCvkzETToM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,50,101,102,51,52,52,
                     45,56,51,51,56,45,52,98,54,57,45,97,55,97,102,45,57,98,
                     101,56,50,100,55,55,53,50,99,54>> =>
                       <<"±3JNr3QB694fdOYWINIVl8sFgBIACleX2QsdPSHvDVpk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,50,51,98,51,102,51,51,45,
                     48,57,51,53,45,52,50,51,52,45,57,48,54,53,45,50,101,100,
                     55,52,99,99,56,53,53,100,49>> =>
                       <<"±QCd9iSiA75DYVw+C1DQztDGaz1nnjS4Bjaa0DlKOgPo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,98,55,51,56,56,48,54,45,
                     102,97,56,51,45,52,51,53,54,45,97,49,56,52,45,98,48,55,
                     48,102,102,54,51,99,54,101,99>> =>
                       <<"±QetCn+3OfnWp1r+fRvxpHBrTCkTv30ThSbT6nVUm1xQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,52,56,49,97,99,52,
                     99,45,55,56,52,101,45,52,54,57,56,45,56,101,54,52,45,55,
                     98,98,48,56,97,57,52,48,48,101,51>> =>
                       <<"±jx9eX6+yeMRLCbFca0OIo9lg1B3Y8aT1lhjfvL4C7cc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,53,55,51,100,57,49,
                     45,52,48,50,52,45,52,100,49,54,45,98,101,98,49,45,51,97,
                     53,101,52,51,97,49,55,54,97,57>> =>
                       <<"±md7Ocu+B5oDQdLQaKnS59qr+45zFgFOVcaaIKM8keSE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,98,98,97,56,49,54,45,
                     53,57,49,97,45,52,51,102,100,45,56,53,102,100,45,102,
                     101,53,102,98,97,57,49,99,57,57,57>> =>
                       <<"±lxYspVus5xKA7y9AHXIppvG0Ox/tzwB7BVlVNiYh44Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,56,54,102,50,99,48,101,
                     45,100,51,102,100,45,52,57,52,51,45,97,98,101,49,45,101,
                     97,98,54,102,50,56,53,99,98,102,54>> =>
                       <<"±ME17VYN14KBvLqQFgPgXpSSZI/ONg65Xt7H5YLWJMGM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,49,51,56,49,98,55,
                     51,45,54,97,101,97,45,52,101,50,98,45,57,48,55,51,45,52,
                     99,57,97,53,51,97,52,100,48,49,50>> =>
                       <<"±nnRm6Yj+PBXMCuqgQdKvUbcepfH5dtdSIIhquE0/LdM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,98,48,49,57,49,51,45,
                     100,56,50,101,45,52,54,50,102,45,98,55,56,50,45,98,98,
                     54,55,48,98,52,99,57,101,55,100>> =>
                       <<"±3hMJGYwj1GfxTECrEXczq+6vdKNyHzT90lOVjRY0iyM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,52,98,101,98,97,57,
                     55,45,99,51,56,53,45,52,49,52,54,45,98,56,49,54,45,102,
                     57,99,99,52,50,56,57,55,48,53,100>> =>
                       <<"±kyfpCvnlG85jjzOgWItjLb5jNWAnBWmgpWYCNM0mvc0=">>,
                   <<1,0,0,0,0,17,107,101,121,55>> =>
                       <<25,118,97,108,117,101,55>>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,49,56,98,51,100,57,
                     45,99,98,53,48,45,52,99,99,53,45,98,51,54,98,45,49,100,
                     54,57,49,50,53,50,54,51,98,55>> =>
                       <<"±+meUpk1tOzA021SsHrFzEJi4AEWQ360LjpONUgu/zZE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,49,53,52,50,50,97,45,
                     53,49,48,100,45,52,48,54,57,45,56,99,101,52,45,55,57,54,
                     101,54,48,54,55,49,49,57,51>> =>
                       <<"±MNhqSqSIoyHTfu5KBSM/Amck/ybJ3HKmXB2P93hBzA0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,53,54,101,55,100,53,
                     45,48,50,49,101,45,52,52,102,56,45,57,54,56,54,45,55,98,
                     49,55,54,55,51,55,55,102,52,52>> =>
                       <<"±iGLMP7kmBgu0IxmKkSm5wK5zE2FbdjOSiXyjAZSJj3E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,53,51,102,51,102,53,101,
                     45,57,54,50,99,45,52,99,51,100,45,97,56,102,97,45,50,
                     100,50,51,101,97,98,102,100,100,98,56>> =>
                       <<"±bPUWYWAK+cQ6E91qY+ETTWqWH1cEswBAQES7t7O6Ow8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,57,100,97,97,51,54,48,45,
                     49,50,98,102,45,52,101,50,54,45,57,56,99,54,45,102,51,
                     55,49,51,99,55,102,48,102,50,55>> =>
                       <<"±kIPmqGABd+g49iBr3MoU+PtViA1DIDS8vRX7CzH8NLA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,97,99,48,100,56,101,56,
                     45,55,101,102,52,45,52,57,52,102,45,97,53,50,102,45,100,
                     56,49,55,52,48,97,56,53,48,49,51>> =>
                       <<"±VT4hdBjnbYPi0zrffkZrWOz8vsFtaIPiNrS85mlz900=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,99,49,99,55,102,
                     53,98,45,97,48,55,97,45,52,56,56,97,45,97,98,52,98,45,
                     102,48,54,49,49,100,56,57,101,53,57,54>> =>
                       <<"±nYKliwL9rPQt3TmEbQUdPtoZiDHvmFi8sdzfbw21FVw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,102,55,57,48,55,48,
                     45,50,53,48,51,45,52,99,102,50,45,56,97,49,97,45,57,97,
                     50,51,50,50,101,52,57,50,53,102>> =>
                       <<"±lB1XGi901mjH3TeUNqrvvjJheEnPpb/zRRqsjy0NkPA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,48,52,99,48,56,49,52,45,
                     49,51,54,97,45,52,102,54,52,45,57,100,49,57,45,101,101,
                     55,57,98,56,56,56,97,100,50,100>> =>
                       <<"±kEDAo1DANkXjC9KUwmjUOIzk5t1fZw+XDNnpb4Km/ck=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,49,100,101,56,97,54,
                     45,51,55,100,55,45,52,53,51,54,45,56,99,99,100,45,97,50,
                     51,53,50,51,55,100,54,48,48,57>> =>
                       <<"±6Qlu313E5YBIeW0Xf7jqnTFPnn4G/5FhwznM0vxnjAE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,100,53,100,102,55,56,
                     45,48,53,49,102,45,52,55,56,98,45,56,55,102,56,45,57,
                     100,102,50,49,52,97,101,51,57,57,55>> =>
                       <<"±W+NXjJrpqV1Gp473zKXIn2ZZ9U/6YADZr1viaUbeteA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,97,102,101,55,57,
                     99,56,45,49,56,54,49,45,52,54,54,53,45,97,52,53,102,45,
                     54,48,50,52,56,51,55,50,98,102,49,52>> =>
                       <<"±+KmqMF18DHILeVbp+VYdgiJ54ywspP9dowwQvZrt3w0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,50,98,101,98,100,
                     52,51,45,102,98,99,50,45,52,99,57,48,45,57,102,53,49,45,
                     56,55,54,57,102,100,101,97,97,48,49,49>> =>
                       <<"±QSVTBZG18o+g9qdwifiH3a7a/5wq2yUz9EkhaKf1JEw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,50,102,97,98,56,55,45,
                     50,54,56,50,45,52,51,57,100,45,56,102,53,49,45,97,48,57,
                     53,54,53,99,100,55,102,57,100>> =>
                       <<"±s91odiWScSSMmc1FvGv16BfSAAmKPlR1l4lvmZcorQ0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,56,48,48,52,54,56,
                     100,45,50,49,97,101,45,52,100,51,52,45,98,48,50,48,45,
                     54,48,102,99,49,99,57,101,101,51,100,55>> =>
                       <<"±2Ht8rfh1CBw8e7WEQWdJXHdFqudO29yKieS2JEB2L8Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,51,102,50,49,101,53,
                     45,97,101,48,98,45,52,55,57,54,45,98,100,51,55,45,101,
                     54,102,52,49,52,54,52,53,57,54,102>> =>
                       <<"±7mzaXnW7Gnn5eW6l+ACe4rlxs0v4Lu2TXn+HQexi0SM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,57,54,97,97,97,50,56,45,
                     52,57,48,102,45,52,49,54,97,45,97,55,55,57,45,48,101,56,
                     101,99,53,97,57,55,102,48,55>> =>
                       <<"±Bx8oJri4QUrV96qhbGJe/X6AqpJjtpeJMdkHsaCLrBg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,97,98,49,56,56,55,53,45,
                     49,51,55,54,45,52,99,57,50,45,97,101,102,56,45,102,53,
                     51,53,55,51,54,53,100,55,100,49>> =>
                       <<"±ImhFp5EKmN+5ygDp97asji50n0h0ifK8cPBZNaIkOnk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,97,51,52,49,50,51,45,
                     99,48,50,50,45,52,48,52,98,45,56,52,100,57,45,52,98,100,
                     54,54,56,102,101,48,55,57,101>> =>
                       <<"±J19mI/x+bcDjsDWR3iU7y8pm2RP4vSWWyPoWsMtkGQY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,50,53,98,98,98,57,
                     100,45,49,52,102,97,45,52,48,57,101,45,98,99,57,52,45,
                     56,102,97,53,51,52,57,51,51,98,50,57>> =>
                       <<"±vPgpJspawAisGoFfecRC+RKJoYigFSMD5A4ouMEItYA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,52,57,52,50,57,100,45,
                     48,99,102,48,45,52,55,57,53,45,97,98,99,52,45,54,97,55,
                     49,52,48,53,56,53,99,50,98>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,102,54,55,48,54,57,99,45,
                     99,51,51,53,45,52,48,55,54,45,98,56,100,52,45,101,100,
                     100,55,101,55,98,100,100,100,55,54>> =>
                       <<"±CI25aTXipmdH5hU6ieSW6gVwjoGr+O+NSDO2rETpOqg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,49,55,102,98,53,54,57,45,
                     50,99,52,54,45,52,51,99,102,45,57,56,53,49,45,53,51,99,
                     49,98,51,55,55,100,52,52,98>> =>
                       <<"±y16rJBiyyuDu0ED5kRT2gHrUeMQ7rS8fxdfWNJ2syAU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,102,102,102,48,56,98,
                     45,56,53,55,99,45,52,49,48,102,45,98,49,53,100,45,101,
                     101,51,56,49,98,51,55,56,57,48,97>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,102,51,49,99,100,102,52,
                     45,50,101,55,101,45,52,98,102,52,45,98,102,49,52,45,97,
                     53,49,53,102,99,102,48,56,97,48,101>> =>
                       <<"±OjLb33J4C1YjFOirDjRt4Buh6601imayQe7YIJMELL0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,97,54,55,102,97,56,98,
                     45,50,51,48,98,45,52,48,54,53,45,97,54,99,50,45,53,52, 
                     55,53,101,102,97,52,53,57,51,98>> =>
                       <<"±SV+yHyYxrdvUG2gvjqV0zEldBGN2/wXnRv+Yb5AG6Io=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,48,55,54,49,101,52,
                     45,98,99,53,56,45,52,100,100,51,45,56,56,49,99,45,98,49,
                     102,97,53,52,53,53,99,51,102,54>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,102,51,57,50,97,56,45,
                     49,56,100,49,45,52,99,53,102,45,98,101,54,57,45,56,51,
                     101,53,57,48,98,97,53,54,49,101>> =>
                       <<"±FtseyNvCASceu5j2Edj9t2RIDVDwCGWwudhDwvl1pHc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,102,98,52,97,53,48,45,
                     54,101,53,53,45,52,98,51,56,45,98,48,53,51,45,101,51,49,
                     56,99,51,98,56,102,50,102,101>> =>
                       <<"±VVrxu1kKUKqI9eOZ3Qewi1v9y8dLWY2QkwqT/YEYznU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,100,51,49,52,49,101,102,
                     45,102,55,48,101,45,52,102,48,99,45,98,100,102,51,45,
                     102,101,51,97,57,102,53,55,99,54,102,57>> =>
                       <<"±wdwIWIg3uLJ1O8ySjeYe8gh8QZNYbvp9NnRmTqKCiOo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,54,101,54,56,97,101,
                     45,50,48,57,102,45,52,100,57,99,45,98,102,54,100,45,55,
                     49,54,102,97,97,55,98,56,97,101,57>> =>
                       <<"±kiW+RCRw2/mKC1p2xXiive0mU7P5WDiW4wTLouEe0oo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,52,56,48,54,101,53,45,
                     98,99,48,48,45,52,48,101,99,45,57,101,53,99,45,48,97,53,
                     49,98,51,51,52,55,52,56,102>> =>
                       <<"±HQtN/8SmpD7D/pD0pOPXNHEbC89LYy2HBrW7Fb4nvnU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,55,52,55,51,54,51,101,45,
                     101,97,50,102,45,52,98,101,52,45,98,50,55,57,45,49,57,
                     52,57,50,48,56,50,102,53,102,97>> =>
                       <<"±GbzsLRb8xvgMj8h2q9wEcL/nUbS+qD1ZUk1R4+jhsAY=">>,
                   <<1,0,0,0,0,17,107,101,121,56>> =>
                       <<25,118,97,108,117,101,56>>,
                   <<1,0,0,0,0,161,98,109,116,95,99,48,48,101,102,50,54,55,
                     45,52,57,54,101,45,52,52,101,97,45,98,50,102,49,45,98,
                     54,53,54,51,102,100,57,55,51,101,97>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,49,49,99,51,57,54,49,45,
                     99,50,56,55,45,52,50,49,100,45,97,49,49,100,45,100,100,
                     56,102,97,97,49,50,102,50,98,53>> =>
                       <<"±Ja2Rhx1lTa0T+gv0UYqIWRvZL0cIOshjwz7KgoOM0lE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,50,100,55,48,50,49,97,45,
                     53,54,97,50,45,52,51,98,55,45,98,101,50,55,45,100,54,55,
                     51,52,55,54,50,101,56,97,53>> =>
                       <<"±MbkCgDAGrFfYYVZG0e6xnNejODwbBPWGeA4r6XfZm3U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,51,56,50,48,56,55,45,
                     100,53,53,52,45,52,98,99,57,45,56,50,53,52,45,101,55,54,
                     101,102,48,101,53,50,55,102,97>> =>
                       <<"±evHtD2SObQ/ZVdp4cRGHJ41VS+MitggJrfl+McO8omI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,48,50,49,49,50,50,49,45,
                     49,56,55,53,45,52,98,98,54,45,97,101,97,48,45,98,54,99,
                     55,56,52,57,100,53,98,56,57>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,102,99,51,50,100,55,54,
                     45,51,57,98,98,45,52,102,51,53,45,57,51,53,50,45,99,50,
                     54,101,49,56,55,101,57,57,56,52>> =>
                       <<"±Qf55mHvUFEEd9msmPHWFwuDZbptJlZh6kMkDlhFsEkQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,55,49,99,53,100,51,52,45,
                     100,53,54,53,45,52,56,57,50,45,98,101,99,99,45,49,99,54,
                     52,97,56,50,55,48,48,54,54>> =>
                       <<"±42sHgldGAj5KgSt0r9KXSLG+mBul+PB7BiFIldoa98Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,50,55,49,51,50,98,45,
                     99,55,48,49,45,52,50,53,53,45,57,99,52,51,45,100,102,52,
                     50,51,97,54,99,48,97,57,57>> =>
                       <<"±794hdrFDx9P2NSmOmQDND7HmG5VC3YWkQxT6+CpYdd0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,98,97,102,97,49,101,
                     45,50,49,98,57,45,52,99,54,98,45,97,53,53,55,45,48,101,
                     98,98,102,48,99,56,53,57,100,55>> =>
                       <<"±hn6zqwkrH7vAUUXJSgAEEAZGJhFYEPdINsb+pLDHdOg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,49,57,102,101,99,
                     49,55,45,57,48,57,97,45,52,100,102,102,45,97,48,49,49,
                     45,102,101,102,52,54,98,99,101,57,102,57,52>> =>
                       <<"±0Pk49hBPdEhFVd9zfRJ5t7pkZlnw7BOL1APYAVbqs1o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,98,49,101,101,97,100,98,
                     45,101,102,97,55,45,52,51,98,53,45,56,101,54,55,45,100,
                     55,51,57,57,98,98,48,48,100,54,102>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,52,52,51,53,48,50,45,
                     49,50,98,54,45,52,51,50,97,45,56,57,97,52,45,57,51,54,
                     98,101,102,57,102,97,57,55,49>> =>
                       <<"±8cNd5dzhTEnvXF0Z2lVnh0SP4o4qsxzzA3aY0IPKOrk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,55,53,57,52,49,55,55,45,
                     53,57,99,98,45,52,48,102,56,45,98,55,102,98,45,51,99,
                     102,99,99,52,98,55,52,97,53,51>> =>
                       <<"±DhEKBRZS7Jb+xsDGGgwij7HHt27b8k2Ma/qaFPs7fN8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,53,56,54,57,99,101,51,
                     45,53,99,100,99,45,52,102,49,97,45,56,98,97,97,45,50,51,
                     52,48,101,56,50,98,50,101,53,101>> =>
                       <<"±RR6hYn1xsGm6lYEnYbDNxCX90MvPXzMyoLCtTkpmnDY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,52,102,99,48,101,55,52,
                     45,49,53,57,57,45,52,100,49,102,45,56,49,49,57,45,99,50,
                     97,54,49,98,54,97,52,100,99,101>> =>
                       <<"±1kJTbSnj9Gk3KZi160VwBtvIGK1xy3gpLipUXJGKdk8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,100,98,97,56,50,55,45,
                     51,100,49,51,45,52,52,54,57,45,97,49,54,55,45,57,54,56,
                     54,52,101,48,97,49,51,102,102>> =>
                       <<"±Y4HY7QxM/AxkOb7fY5hssAYyyKwV63JinrdjwJN0iUo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,54,48,98,51,54,99,99,45,
                     101,49,52,99,45,52,101,57,53,45,57,52,101,57,45,98,56,
                     102,50,57,53,53,49,50,54,54,51>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,97,57,57,52,99,100,
                     45,97,102,101,52,45,52,99,55,98,45,57,56,99,48,45,54,54,
                     48,50,101,57,48,56,57,52,55,100>> =>
                       <<"±WpCTiBMcS+VmTKJps4JL6fQfwxaTbqkGRYBB7zf96mE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,51,49,101,54,50,56,
                     45,55,51,55,52,45,52,50,98,51,45,97,56,56,99,45,99,102,
                     57,51,102,57,53,56,56,51,51,53>> =>
                       <<"±jpkGGcVqDV4N1EN8h61mfk9DgMapNXfzGwHu9vg0HVw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,53,97,97,56,52,53,
                     97,45,55,99,52,52,45,52,52,102,49,45,56,56,57,52,45,57,
                     100,101,48,102,50,52,55,52,55,102,48>> =>
                       <<"±6iUoRm+imD32jmpjsQ7m4RNnF5OwObCjg3Om5EOyA1Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,54,101,50,53,99,52,97,45,
                     53,100,51,99,45,52,54,101,52,45,57,54,53,54,45,99,97,48,
                     54,48,99,102,55,56,56,102,57>> =>
                       <<"±E3riJtYEVVkYCiOmLPbvO+W9zOjimC9blRAeYiQxZNs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,56,54,48,56,102,48,
                     45,50,49,53,98,45,52,49,53,56,45,57,102,50,49,45,102,56,
                     102,49,102,100,99,51,98,52,56,102>> =>
                       <<"±wAygqrxXtzVKfD12Qh/cAXhijoUNI0rUY4Z9CjM5Nn8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,54,55,52,52,53,57,45,
                     57,57,100,54,45,52,54,49,53,45,98,53,52,97,45,102,102,
                     54,101,51,57,101,48,51,98,50,97>> =>
                       <<"±gtVeDJYr+hNoS1gHiIdl2Pc5qPh91CRQ1OoBUdqQvKI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,100,101,57,101,99,
                     54,102,45,57,51,51,99,45,52,56,49,53,45,98,98,98,101,45,
                     56,49,50,51,54,53,49,54,101,57,54,54>> =>
                       <<"±6TuIuohyGXpx6OIoHBMYcxTvvJuXtNvHmNZgbLA5jz0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,48,54,52,50,98,50,45,
                     50,50,50,98,45,52,51,99,51,45,57,50,52,50,45,56,101,57,
                     57,52,49,102,49,99,56,51,97>> =>
                       <<"±w8vS2yZ9/eXNsWae1NpluxmU+wjncdpmL5Yi8s6P9I4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,51,97,99,98,97,49,55,45,
                     52,48,101,49,45,52,52,97,48,45,56,101,98,100,45,101,101,
                     100,55,99,51,98,57,98,102,53,54>> =>
                       <<"±eXFy8PnN5QUf170hgevBp1nCWS5CMiT/wR99u5VHotw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,97,54,54,57,101,54,102,
                     45,56,57,100,53,45,52,49,100,56,45,57,57,99,53,45,97,
                     102,51,101,102,49,51,53,51,101,98,99>> =>
                       <<"±9ak9YFaUMxD8qYMfKwwg+f31dlEFMVTo/V2aSHYDj64=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,97,57,55,100,57,57,97,45,
                     100,56,98,52,45,52,101,56,97,45,98,50,98,101,45,57,100,
                     50,99,55,54,52,54,99,51,99,98>> =>
                       <<"±4WOIWjWq/sXJcFW+iH/76abxkJADFkXuRFA6muB5Oos=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,48,100,53,98,49,55,102,
                     45,97,101,98,53,45,52,49,48,55,45,56,102,102,56,45,55,
                     97,53,57,54,48,57,99,99,99,98,53>> =>
                       <<"±4yO7F5tPCtG7AzFXW3SNhOLuppXVRL8kRTF6oTDNPxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,48,99,49,98,48,98,45,
                     54,48,97,101,45,52,51,100,51,45,98,54,50,49,45,56,101,
                     53,102,56,55,53,49,51,56,50,57>> =>
                       <<"±J5SAZPRHfP+6Vp585puvNduP0mO05QC8HaLIE2fTFYo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,55,54,56,101,101,99,55,
                     45,55,55,54,50,45,52,100,48,99,45,97,98,100,98,45,49,54,
                     98,54,98,50,99,57,99,102,51,55>> =>
                       <<"±mG4jxDUSl2KcdWhMVG3zA9ytuxBQttGVU6QXGP+iG7s=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,50,52,98,55,102,97,45,
                     54,48,100,52,45,52,101,48,101,45,97,54,99,52,45,101,48,
                     100,49,52,55,52,102,55,48,49,54>> =>
                       <<"±AFQwST6gp7Heguy8nGul1HZKKg8/k0Q4imfC/G+Lp3o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,99,49,99,56,54,101,55,45,
                     102,51,102,51,45,52,102,53,56,45,57,51,50,101,45,56,52,
                     48,54,50,56,51,52,99,98,100,97>> =>
                       <<"±IP5jqug3r6aCjKwN2EI5SWvWenF+W1Ml1gt8Qhfldjo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,51,56,51,56,50,99,45,
                     100,97,53,97,45,52,51,98,97,45,98,49,100,48,45,49,48,51,
                     100,54,48,53,54,100,49,101,48>> =>
                       <<"±vHqVump/vQIHiudJK8VgsMktNJz8GpO7tWZQN2V/s4Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,52,52,51,97,51,57,45,
                     102,57,54,55,45,52,100,97,54,45,98,50,54,101,45,54,102,
                     52,54,54,53,98,55,48,53,52,97>> =>
                       <<"±8DQnr7N3I+ITzSpvlbupM4OrRKJ5SqKg6ehOQT0v17M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,54,55,97,53,102,100,
                     45,52,57,56,100,45,52,101,102,51,45,97,51,49,101,45,52,
                     101,48,102,98,52,55,55,56,49,100,101>> =>
                       <<"±R2NkMQ1FnngMXQeEznHX0T/CE+4UvklYDoLqx01oRr0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,52,51,57,54,54,50,45,
                     97,101,52,100,45,52,101,54,55,45,56,97,53,48,45,97,49,
                     53,98,97,102,56,56,97,57,57,48>> =>
                       <<"±UWo/p/8i/2MWA+5pY9caWo6R/HpiQHT7XyfmXxcBTWA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,100,56,48,48,54,
                     100,48,45,51,48,53,99,45,52,98,50,49,45,56,99,51,48,45,
                     48,49,98,97,54,98,50,99,54,99,102,98>> => 
                       <<"±oS8YXVkAjBgOYbfNJNYUt8VAL3Dcu81YnqPFHthGXxk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,57,53,52,102,100,57,
                     45,98,53,100,100,45,52,99,53,51,45,97,102,48,99,45,98,
                     102,101,48,100,101,48,55,57,98,49,100>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,51,101,101,56,53,101,
                     45,55,48,53,101,45,52,48,51,56,45,57,101,101,56,45,97,
                     102,100,100,48,99,55,97,102,57,98,49>> =>
                       <<"±nOlrkZPh5ahhPK5/B6xNmRi8QKpDunkmZTi8som/SAI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,48,101,99,49,50,49,45,
                     97,100,52,52,45,52,48,53,97,45,98,51,48,49,45,54,54,57,
                     100,102,55,49,52,57,56,101,55>> =>
                       <<"±1r1I3y3eMW5RWOZCzPJIwvIzuU5Ezon/X83S9wmaQYE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,56,97,51,102,55,101,
                     45,98,57,101,54,45,52,100,97,50,45,98,56,56,48,45,53,57,
                     52,52,101,100,56,53,56,54,55,51>> =>
                       <<"±68Eh1iah9R6wHANkKPoFRxsvceQtwxF170VabfjGoAw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,98,101,49,102,53,98,
                     45,51,101,52,101,45,52,97,56,54,45,56,101,99,100,45,102,
                     57,50,49,99,54,50,54,51,54,101,56>> =>
                       <<"±//RANrlkvp8xsJMP24Baw1M33vbDZgaS5HCZblcMSoY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,55,52,55,98,99,52,
                     50,45,99,48,97,48,45,52,51,99,98,45,97,99,55,52,45,56,
                     97,101,54,48,50,52,102,54,100,57,100>> =>
                       <<"±XqiFccUwLVWPte8fDOlFuh5O5Ia0x4T+gsP5gZAL9xc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,99,55,49,56,102,55,
                     45,102,53,57,98,45,52,97,100,98,45,98,55,56,98,45,101,
                     48,102,57,50,51,98,48,56,49,53,51>> =>
                       <<"±v39VE/k/+UZMB/8X1mEl9bDMFIEGGP6ATZPfLERAPNM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,50,101,54,55,48,100,49,
                     45,97,49,57,99,45,52,97,101,101,45,98,100,50,98,45,56,
                     56,55,54,48,52,51,97,98,48,51,55>> => 
                       <<"±mlzfVnZn2BK3P0fP7ryWkV7iTZhEmzPkRifEvHwo7Yg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,57,97,54,99,57,48,
                     54,45,102,51,54,49,45,52,102,101,55,45,98,50,56,99,45,
                     50,49,55,52,49,55,101,101,53,52,52,99>> =>
                       <<"±lG4nl2yB3d3mD5ZTn4Dym2ZR87y/Fa4gUi9ORQNybcY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,56,102,51,48,98,52,45,
                     50,49,52,53,45,52,49,51,101,45,97,48,50,51,45,97,56,50,
                     53,56,54,49,101,57,48,51,50>> =>
                       <<"±QVhXitrg6Q5rZx7/ZUBy79P9cJYAv0jdjMRd+N/1bPY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,50,51,101,49,55,56,100,
                     45,102,48,99,48,45,52,53,50,53,45,98,101,48,57,45,55,51,
                     48,56,54,48,100,100,51,54,49,56>> =>
                       <<"±vJNaLHscq+lSSf7Cind3M+NjQL+dDZhRYazeg2AoeF8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,49,99,98,100,53,50,99,45,
                     53,100,101,102,45,52,101,99,55,45,57,97,48,51,45,49,55,
                     98,98,101,97,101,57,50,54,98,55>> =>
                       <<"±fFKEmen3Za27uw4KI0q1x2XtsanY8tEC4cgpN3F5ids=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,52,52,51,55,53,49,53,45,
                     49,99,48,102,45,52,55,52,100,45,56,52,100,53,45,99,53,
                     49,97,51,98,102,51,100,102,100,55>> =>
                       <<"±wG+IVXdWxsI1hWeCFbXGAhELZQ2GS5upBdTRFWwipcU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,101,54,50,51,50,52,48,45,
                     53,52,53,57,45,52,102,56,51,45,97,102,52,102,45,51,57,
                     51,50,55,57,52,48,98,101,101,100>> =>
                       <<"±+6Wzrn9g4V4jmWgoHkHr8VZpo6t6JisDGV3S/nGLrNU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,56,55,48,49,49,53,48,45,
                     48,101,98,52,45,52,51,102,102,45,56,49,99,56,45,53,49,
                     57,97,101,57,48,97,54,100,53,51>> =>
                       <<"±/5Dm44DTaRd+/0o5sA7/Q/EZsg3LGNyT47MJSNXvC3g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,52,53,57,50,55,55,57,45,
                     53,57,57,54,45,52,97,100,49,45,97,56,57,102,45,57,52,
                     100,52,54,56,55,100,57,99,101,101>> =>
                       <<"±75wSX7qiExckzQtbEfX+Um0jwl0G/GogBQy9oaFRmsQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,48,52,48,52,55,102,
                     45,56,49,50,50,45,52,53,53,54,45,57,52,99,53,45,54,100,
                     49,99,50,48,57,99,56,54,51,51>> =>
                       <<"±uUBDbYDH53AO4H4bW03jy02eEQslh5iPfNY/Er1/LXg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,57,99,56,97,49,50,57,45,
                     52,97,54,102,45,52,51,97,56,45,97,56,53,57,45,52,50,52,
                     102,53,101,101,101,56,50,100,48>> =>
                       <<"±FUllTYAnUXJ98JDb8NM3qvt+mKKu6Qs53IvtI5gKohc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,56,52,98,52,55,97,
                     98,45,54,101,56,51,45,52,55,51,54,45,98,49,102,55,45,50,
                     97,101,57,51,102,102,102,55,98,48,55>> =>
                       <<"±QXempctQs1jD0w6waU2+aQa0us3gBF8ARoswLRGDd1Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,98,54,49,53,101,56,50,45,
                     102,48,101,101,45,52,48,99,100,45,57,101,101,101,45,98,
                     101,97,56,55,49,98,57,102,54,55,101>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,51,98,57,54,49,49,100,45,
                     55,97,49,50,45,52,51,102,54,45,98,53,50,97,45,54,101,57,
                     98,57,102,48,101,97,100,98,98>> =>
                       <<"±/7tqkg1QKvinF1VjS/kQKhMyaEokp+Tj6n732llnCZY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,102,100,56,57,57,49,
                     45,102,55,51,53,45,52,98,49,56,45,56,55,102,50,45,97,
                     102,56,98,99,53,50,51,52,49,56,50>> =>
                       <<"±FegtdQb0KC9rmjXrwLVucvh3+HqBpX8WbiBaGD+jTlU=">>, 
                   <<1,0,0,0,0,161,98,109,116,95,101,57,55,50,54,100,54,97,
                     45,57,99,48,56,45,52,97,102,56,45,56,52,100,48,45,48,97,
                     51,100,98,97,49,97,53,52,56,54>> =>
                       <<"±BZ9zBzqTeetEAS/3/8Y1qpSModdpvQLoV0y9zgbByv8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,54,51,54,48,99,101,57,
                     45,57,102,55,49,45,52,52,101,55,45,98,52,50,55,45,102,
                     51,101,98,54,52,55,49,48,48,99,98>> =>
                       <<"±XF4sr/jhnKQwprUisM2hFFCsbqsRGimBHkGOehW9BRg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,50,50,102,56,51,51,
                     97,45,99,98,99,55,45,52,52,49,98,45,56,98,50,52,45,56,
                     48,51,55,51,97,52,54,99,48,102,54>> =>
                       <<"±Oagch1yI8DIFfKuwRzXBpjxfPCwNAE2aTKF1CQj1bvA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,49,97,98,101,97,50,45,
                     56,52,56,101,45,52,98,101,52,45,98,99,98,48,45,54,48,55,
                     48,48,101,50,53,51,100,56,98>> =>
                       <<"±fmejSUVM7UZM9OTjJ4N5gNK4pL79DxSG8ZeDwPb+Inc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,53,102,49,53,99,99,45,
                     52,52,98,56,45,52,98,99,102,45,98,98,57,57,45,50,54,52,
                     53,52,51,50,99,102,57,49,55>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,53,54,55,56,48,48,45,
                     55,51,56,51,45,52,54,97,57,45,56,52,56,53,45,52,49,99,
                     52,101,54,55,56,50,56,98,52>> =>
                       <<"±nvIXni4pN170gkZWqJWzbEn+qzepHHeIyrlJbt0nZ1A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,57,99,98,50,50,49,45,
                     49,48,97,98,45,52,53,100,51,45,57,102,98,52,45,56,54,53,
                     97,99,97,51,50,97,97,57,101>> =>
                       <<"±vBUIvEgW4i//acVNxfaa0JwD9CgIN8FZ1E01iSLigcw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,51,55,56,55,99,57,50,45,
                     101,99,57,100,45,52,98,49,56,45,98,48,49,99,45,57,55,52,
                     100,50,53,101,99,56,54,48,102>> =>
                       <<"±CjmcPaiEJHWOMGoITeUSH6QodJ0U5eJXTtkiqI9hMGM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,99,98,56,101,97,57,
                     45,55,56,52,51,45,52,98,97,102,45,98,100,102,100,45,54,
                     54,97,55,56,49,57,56,57,50,102,56>> =>
                       <<"±RfQaa47Am28uX+BcWoBhr0KnWv+8YERVGvQEmspdYaI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,52,55,48,100,48,56,
                     45,56,97,50,51,45,52,52,50,102,45,57,100,102,102,45,99,
                     101,48,52,52,57,102,99,53,51,57,102>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,55,98,48,52,100,52,57,45,
                     56,57,57,102,45,52,49,52,53,45,97,50,50,99,45,48,101,
                     101,54,97,49,50,101,48,52,57,49>> =>
                       <<"±hde9YGbiijOkfo7UoDyGgTKd535+iFOUywNUe841ulY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,56,55,99,48,98,99,
                     50,45,55,102,53,52,45,52,48,98,100,45,98,98,48,51,45,
                     100,98,53,56,50,102,99,97,55,100,99,98>> =>
                       <<"±tne9Vi4IZV4Vs/RDveFetg+iOft1vs4PIY2GLbV3qC0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,55,100,97,100,52,100,53,
                     45,101,55,54,50,45,52,54,49,101,45,97,55,55,56,45,56,
                     100,50,52,52,100,48,55,56,56,98,102>> =>
                       <<"±hRUNgz4cLu5IofDob3DugpN4DIlJJfmBf1mbLCt6/MY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,101,101,102,97,56,49,50,
                     45,49,97,101,56,45,52,55,48,102,45,56,97,56,51,45,100,
                     53,48,102,50,99,52,100,50,57,50,99>> =>
                       <<"±qOEjtiCsRontvpOrbQdUbSfcrL3lYZQt8ttnrfcJDrw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,51,53,99,101,102,
                     56,50,45,97,97,55,99,45,52,49,98,51,45,97,57,49,102,45,
                     49,52,48,102,100,99,99,51,99,100,100,99>> =>
                       <<"±z/E9oPgXlHO4DSGhrIoE3rbGNmhy5xnlzJIkltevSto=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,97,57,98,49,100,98,45,
                     99,52,99,101,45,52,98,98,101,45,57,98,98,98,45,57,52,
                     100,102,48,54,53,56,49,54,102,99>> =>
                       <<"±jjstNL8cfTq5Pmi8U/YTZrGRW0DNiYCOIZ+9RkhIJvM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,55,48,56,54,54,49,52,45,
                     53,57,102,57,45,52,55,52,98,45,97,99,56,98,45,49,102,50,
                     55,48,53,97,48,57,98,48,101>> =>
                       <<"±dtHv+iUy8B6iL0mARYJR44eoIEzlqZ3AnYzNmKNjAWs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,102,99,102,56,98,55,
                     45,100,48,51,49,45,52,52,49,101,45,56,51,51,100,45,97,
                     57,98,101,56,98,101,55,51,53,57,54>> =>
                       <<"±2snEr6sNrNyZoTfPjJmtrepktBOk4q51vsSpGJKpyko=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,55,49,54,50,53,51,57,45,
                     50,102,98,49,45,52,100,55,51,45,97,49,57,97,45,100,53,
                     56,98,52,49,98,102,100,57,55,48>> =>
                       <<"±1uw17dgqwUv7q0hQTE68YghIDKBEJJcFvdCXUKdnmaA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,50,52,97,49,54,49,102,45,
                     50,50,49,100,45,52,52,51,51,45,56,97,54,57,45,50,53,49,
                     98,50,51,56,54,98,101,51,55>> =>
                       <<"±JFG1+E+IHX7STfOWtSrUgRXjfM7HkrJ5V87sAXV/5H8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,54,99,48,102,98,102,55,
                     45,49,55,102,56,45,52,99,50,101,45,98,100,97,53,45,98,
                     101,51,99,97,54,49,99,51,98,98,100>> =>
                       <<"±AIyIzypPBUTSMlHmDPuqJKs33TuwbybBkI2Ca/9HwjM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,51,100,57,49,100,53,101,
                     45,49,57,100,98,45,52,57,98,51,45,97,102,97,54,45,48,52,
                     54,98,98,54,98,98,55,98,49,56>> =>
                       <<"±k8VqeOME4PUvGFVC0dpXvzXghlL/JcraRbNlAMdGxrQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,101,98,97,101,99,55,52,
                     45,49,49,57,55,45,52,48,57,56,45,57,51,102,53,45,100,48,
                     48,53,101,100,53,52,102,102,51,97>> =>
                       <<"±fOdJgIWzw6cP+z/vgZxAvzZjdJpHWCsbNgF7drAkLp8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,50,51,98,49,57,51,45,
                     52,48,52,102,45,52,57,48,54,45,57,99,57,52,45,51,57,49,
                     97,51,52,101,50,56,53,48,53>> =>
                       <<"±ir4A1FDw7JRTEf6RANcy6WDCZhuVtollJkwlRyV6mbE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,98,49,101,56,50,102,
                     45,98,101,51,50,45,52,101,56,54,45,57,48,52,57,45,55,97,
                     102,49,55,57,98,49,51,52,56,101>> =>
                       <<"±nIXUGGuCesluubnVGgr4hzJ6aSBO7q6Uk21ptMFOu5A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,52,51,101,98,55,100,102,
                     45,56,51,49,52,45,52,101,49,56,45,57,98,55,51,45,50,54,
                     51,100,53,101,100,49,50,54,50,102>> =>
                       <<"±VN6ZsKqvLOy8WfE4wLCsypdCMI1POA3/2ZnGp0HmpzE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,54,100,53,102,51,97,
                     45,51,97,57,50,45,52,48,100,101,45,57,55,52,57,45,100,
                     49,97,100,52,57,49,50,99,97,50,55>> =>
                       <<"±yXHRScBN67FotjMAc2UpyXy+jHLXl26s568AXraa+rA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,101,48,57,55,97,100,102,
                     45,97,51,51,55,45,52,56,101,100,45,56,52,51,55,45,49,48,
                     57,102,100,102,48,97,52,54,102,56>> =>
                       <<"±SiFYOuofBlkzzas4a3d+JBDzG+pXFRj/c1aDnRWWfeQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,101,49,52,55,100,102,
                     45,51,53,56,57,45,52,56,51,99,45,97,99,50,55,45,49,57,
                     97,53,102,53,54,55,102,52,102,48>> =>
                       <<"±kDkYw26qPCcjzYSaKG721BbflJHGG1tTbGBd7jKxhLA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,53,55,55,97,102,97,45,
                     48,54,97,51,45,52,48,52,56,45,57,99,53,100,45,98,49,51,
                     97,57,53,98,48,53,102,99,53>> =>
                       <<"±ZIIEpcl0ahvcuatX8BoLUCKylWT6zls4bRCjkSPzuIE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,98,53,99,97,54,97,101,45,
                     98,101,49,53,45,52,97,98,54,45,57,49,101,55,45,98,51,50,
                     101,100,54,54,57,102,97,51,100>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,100,49,97,50,56,53,
                     45,53,52,100,49,45,52,97,48,51,45,97,48,52,97,45,51,55,
                     102,52,98,99,48,52,98,57,97,49>> =>
                       <<"±dZCm2KAvC4PWMqTvJWqOgaBXiKrehIENL0XT+Z5fNBg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,100,50,57,49,50,99,45,
                     50,57,54,98,45,52,50,51,53,45,57,49,97,49,45,99,53,55,
                     98,54,50,50,99,102,53,99,57>> =>
                       <<"±+HtAJKSZq3i7NzHLC2VTIwMFq8uwOdud3FEfi+EoFRg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,55,57,48,55,50,56,49,45,
                     57,55,98,53,45,52,52,53,56,45,56,55,52,48,45,97,50,56,
                     48,52,100,54,48,55,99,101,53>> =>
                       <<"±t4SaCtkZSjFbviMslumh5m5T2GzwDatMLmCpOZs3Xtg=">>,
                   <<1,0,0,0,0,17,107,101,121,50>> =>
                       <<25,118,97,108,117,101,50>>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,53,102,56,53,98,50,45,
                     98,55,49,49,45,52,53,55,57,45,57,57,54,97,45,48,99,53,
                     55,102,55,99,57,57,99,55,57>> =>
                       <<"±ZtdsN9JJYNqxuxBqkLoTol7G/q/jAXwwm6hu1UA13LI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,98,100,48,57,101,52,101,
                     45,49,97,56,102,45,52,99,57,98,45,98,53,55,102,45,102,
                     98,52,56,54,57,100,52,101,51,49,97>> =>
                       <<"±2YMr7svKShReZV+0Iln/7r/pc11n6QS0Wa6ETNsaBIs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,102,52,54,55,97,55,45,
                     54,49,49,50,45,52,102,98,56,45,98,51,55,56,45,53,52,55,
                     100,56,55,50,49,56,101,98,51>> =>
                       <<"±2Z3n99HDTYpdeVPbIHhGVQssPxRfs71EwoEDT7OmVj0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,55,54,51,98,102,
                     101,54,45,55,52,99,51,45,52,57,102,53,45,57,56,100,51,
                     45,97,101,52,56,101,98,97,53,102,57,100,57>> =>
                       <<"±6twASBvJF55Hw7w9kOnIbXNTdEZ3nTg707UX58kVnQc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,52,57,102,52,49,52,53,45,
                     101,53,54,99,45,52,48,48,55,45,56,101,98,50,45,52,100,
                     56,102,49,54,102,97,50,56,53,56>> =>
                       <<"±A6aTNOTFS1ZIKzznjVStc78mWcWHletQylt75CUEw7E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,100,57,48,53,54,51,57,45,
                     99,50,51,55,45,52,51,101,57,45,98,98,52,50,45,48,100,54,
                     56,98,102,99,97,52,50,100,52>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,48,99,102,56,54,53,45,
                     101,50,100,99,45,52,101,57,102,45,57,98,102,57,45,102,
                     51,55,54,101,50,50,102,56,102,55,48>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,48,52,98,97,49,48,45,
                     98,57,56,98,45,52,102,52,57,45,56,48,97,55,45,102,102,
                     102,54,56,102,53,52,102,48,102,53>> =>
                       <<"±CasvxpqcHptB2swIKy1e44hEDjj6DzPA712ZCy7df30=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,54,57,49,54,102,
                     102,49,45,100,98,100,51,45,52,55,100,101,45,56,99,99,57,
                     45,99,54,50,50,97,101,51,55,50,50,57,98>> =>
                       <<"±hiBUMO7KJFDMi8TNm4KnWLx9GkqwAyvNcO4TFsAD/IM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,52,99,54,101,56,51,45,
                     102,55,55,52,45,52,51,99,51,45,57,56,54,56,45,97,56,101,
                     97,54,57,102,54,51,100,57,101>> =>
                       <<"±I60cEdd1yIPEEbUBhwRt/95hZPlx2TgBxpdCsn5Clhw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,50,97,97,54,50,54,
                     102,45,100,49,50,98,45,52,55,57,50,45,98,53,50,54,45,51,
                     51,100,100,51,57,53,99,100,97,52,56>> =>
                       <<"±PU9uU/6kBxDU9FXI9A7hg8gLHVhajA9ysDEhop3ELtM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,51,52,100,102,51,49,50,
                     45,101,101,102,52,45,52,100,49,56,45,56,52,101,101,45,
                     52,52,100,51,51,51,51,51,57,97,52,101>> =>
                       <<"±Ajn3V5P1NBjqKmNJuFeeB6hHFy3LPEUahWQTI3rwQVE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,97,101,52,53,102,48,99,
                     45,54,48,102,49,45,52,102,55,97,45,57,50,100,54,45,51,
                     49,100,55,48,54,54,51,50,49,99,51>> =>
                       <<"±NWHUtLiZOpkdNA5rcCWDAbKUD3tQQzNl4qHMZrMucFM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,100,55,102,98,50,99,51,
                     45,101,55,48,99,45,52,54,101,51,45,97,51,101,48,45,53,
                     52,55,50,98,54,54,101,49,55,48,53>> =>
                       <<"±+sL5Jh+QFsW9mqnaUZIgWNuINQqBI7Vu7yTXkcbCflM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,101,57,56,49,51,52,45,
                     49,54,101,97,45,52,51,53,98,45,56,55,99,99,45,97,100,97,
                     48,52,54,56,48,53,101,98,51>> =>
                       <<"±HYf/ZBmQkNenj4Y5l3vOE2TafWhFDNl9kE9v9EC9fJg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,97,55,98,102,52,98,
                     100,45,48,102,100,53,45,52,51,98,55,45,98,51,49,49,45,
                     56,51,98,51,99,48,50,54,55,53,50,97>> =>
                       <<"±uaBt7noPygsFhJ5B9y7XT1Bqqj46yAvHNA1zo/e29hI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,51,53,49,101,99,53,
                     100,45,54,52,100,54,45,52,49,48,48,45,97,56,102,99,45,
                     51,99,101,50,97,55,57,51,101,51,101,50>> =>
                       <<"±q1gjMfEmsStWukzEcEpxhIOQT6WCuFRxXVTo6FfhjGQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,100,52,51,101,102,98,
                     45,99,99,51,50,45,52,49,99,57,45,98,57,57,55,45,97,100,
                     50,99,99,102,55,101,50,56,98,48>> =>
                       <<"±46K/vTLy72svG2mLI3Ukpb4TIIncR/SocZZMEMzIAAQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,52,100,55,52,100,54,
                     45,54,53,99,55,45,52,99,53,49,45,98,57,50,101,45,48,51,
                     98,98,101,57,101,48,57,98,97,99>> =>
                       <<"±AteSlDOROCJ7Xx9A/dNi4HD1GpkjXi8xH/idhWyEx2k=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,101,48,49,49,48,101,
                     45,52,99,50,55,45,52,99,57,49,45,98,56,52,49,45,56,99,
                     48,50,97,56,49,52,57,51,53,102>> =>
                       <<"±kZNIEM9BI9VuEle5ZtFmdAWAC/oU4SP87pMMEeW3oME=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,100,55,50,50,101,99,53,
                     45,52,51,48,97,45,52,99,100,53,45,56,99,53,100,45,57,
                     102,54,54,52,100,99,51,52,52,52,99>> =>
                       <<"±b1po6Ef1efHYPQUbAXRYbuHZOCEZp8H/tvI9BKhOeyo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,101,100,49,54,55,54,
                     45,97,53,52,101,45,52,56,52,101,45,97,57,97,54,45,55,56,
                     49,54,55,102,50,53,55,101,57,99>> =>
                       <<"±+mJG/9IiV0omXmc9uXoXJhg+BClckIrUlDanirPoC3g=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,99,98,98,98,101,
                     49,48,45,102,53,52,51,45,52,56,48,53,45,97,101,51,97,45,
                     56,54,97,54,102,55,101,56,97,99,55,50>> =>
                       <<"±gtjQK4VbqOh3awxWqUYk4E1VcZW1YplgzHqiHYbnnoY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,55,97,99,52,48,54,51,45,
                     49,54,50,50,45,52,55,48,56,45,56,52,57,99,45,49,54,102,
                     97,55,51,55,54,98,50,102,56>> =>
                       <<"±l53X889yvlL7kqJ7QKjPj50aeaK6EdLhOX42J51CUPA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,52,98,54,97,102,50,
                     57,45,100,56,57,52,45,52,48,99,56,45,56,54,100,101,45,
                     97,97,100,101,48,50,102,52,50,54,49,101>> =>
                       <<"±f8GTD8u2NpweT8TknM77/gSsgkjVPQvNKhXJ3Uuq7QQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,97,54,51,102,56,53,
                     45,51,49,53,53,45,52,50,56,52,45,57,97,48,49,45,97,54,
                     55,56,53,97,56,53,53,48,55,99>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,57,97,99,99,51,57,99,45,
                     50,99,98,49,45,52,57,102,102,45,56,50,53,98,45,55,97,51,
                     49,101,49,49,52,55,97,52,56>> =>
                       <<"±Wypco5Axoz/LwyIMCUf2YqGeNNhZSdduMrTg+fyDCoA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,100,56,55,53,100,49,
                     45,50,101,48,48,45,52,57,56,56,45,97,56,49,102,45,52,
                     100,50,56,100,53,57,55,51,51,102,54>> =>
                       <<"±7W0Kcbhyo/d7QrFr1/Y62zstePyuevXaFhnUgYpA980=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,98,49,98,51,100,54,45,
                     51,102,57,101,45,52,49,99,53,45,57,49,53,97,45,56,101,
                     52,57,51,100,51,53,57,55,54,48>> =>
                       <<"±gCx8T7KBF45Y5/CbkBXTHiD6M4VRbrBAD8/jWtGiG9Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,101,98,98,50,100,56,
                     45,55,57,102,50,45,52,99,56,53,45,57,56,48,48,45,54,54,
                     55,100,51,97,101,55,102,101,102,49>> =>
                       <<"±l3udBCO+TZcj5r/hUhYm8NudTuMD5QMV+2JBsZ8i13I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,55,51,101,102,100,102,56,
                     45,54,49,53,52,45,52,56,50,56,45,97,101,55,100,45,49,50,
                     57,48,54,57,102,99,56,52,98,56>> =>
                       <<"±rFXNUq30YdTULjjb1xcicr+5ToMxOvEzQCdyQqujdLM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,98,48,98,55,54,100,98,45,
                     99,48,97,101,45,52,100,102,53,45,57,99,57,101,45,51,102,
                     102,48,57,54,52,57,57,100,98,101>> =>
                       <<"±cbhXXEVnqeBmRxQpRF3hekf2ptJnUuleKrndzTm3rS8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,51,98,49,48,52,53,45,
                     101,102,52,99,45,52,52,49,54,45,98,51,50,50,45,50,100,
                     56,99,50,101,100,48,56,48,98,100>> =>
                       <<"±wlmnpklhYvCiGmkQ8so2G86isB4g9B5fInijOzPBz5g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,57,53,97,52,52,56,45,
                     99,101,48,100,45,52,54,49,50,45,98,50,53,57,45,54,102,
                     101,98,100,100,102,51,53,51,98,53>> =>
                       <<"±k8zRtEbiQ2j1nyOknH8Y1eFqDTnpbI+PzUW4t9S9DVo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,98,51,52,97,56,52,52,45,
                     53,53,98,49,45,52,100,54,49,45,56,48,98,99,45,50,51,55,
                     97,56,55,54,102,97,53,53,48>> =>
                       <<"±SMV/v467RoqEWWvCNyyUq3KDXKfjGcmdhei9laAH9+A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,101,97,48,57,49,49,45,
                     102,56,98,48,45,52,97,48,55,45,98,52,99,97,45,57,102,99,
                     97,57,54,100,48,102,97,97,49>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,100,50,54,57,56,49,97,
                     45,97,98,49,48,45,52,100,57,51,45,57,54,51,98,45,54,49,
                     56,56,51,54,57,50,102,56,49,102>> =>
                       <<"±wWSk8g7fbsc1WD64aZzXoW7HahBSEIuGcGpYlBYyrNM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,53,53,99,49,101,99,45,
                     53,51,54,53,45,52,97,54,56,45,98,57,51,101,45,101,50,56,
                     101,51,50,49,102,55,100,100,52>> =>
                       <<"±mGrTdhFg0GtmZ/LJTl+PmOimAiV4JUiJbs4FnUAhH6w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,51,100,99,51,52,
                     100,51,45,102,50,57,99,45,52,57,99,55,45,97,56,49,97,45,
                     97,97,53,98,52,55,56,98,100,50,56,101>> =>
                       <<"±pX0nZezxQ4G12n0PDCvDA1XUPwkyKqekK0iFKgQThYE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,48,100,51,54,55,56,52,
                     45,100,56,102,55,45,52,50,55,99,45,56,54,55,54,45,97,
                     100,52,102,48,57,56,49,102,50,55,97>> =>
                       <<"±n2CZpY+zrMXfhOchVZWG1uvHqgBVJEE889PHy9Aw3Zc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,48,100,101,51,102,
                     57,57,45,56,57,54,56,45,52,101,48,98,45,56,55,100,52,45,
                     55,48,50,101,53,102,52,50,56,54,48,57>> =>
                       <<"±BcblFQfgkmrROPn8Uzbi8a5Lv8waZ3dwq7VML6wMyvI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,56,56,52,52,52,102,49,
                     45,54,57,101,99,45,52,52,102,57,45,97,48,54,49,45,52,98,
                     97,100,100,102,54,52,52,99,97,102>> =>
                       <<"±pJkKUiNgOcCP5v+WVj9fN/ArkG3c6rSL53agMZEFGwc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,50,100,102,99,51,102,99,
                     45,97,51,51,99,45,52,53,52,55,45,56,98,53,102,45,53,48,
                     48,51,52,51,99,56,57,99,99,102>> =>
                       <<"±0I/otIqLJjX4jWwX8CA2vIrPxyWYep6ZCesgQFqVPdY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,57,48,55,52,51,102,97,45,
                     98,102,55,52,45,52,53,51,55,45,57,55,100,51,45,49,55,49,
                     56,52,98,100,50,51,102,52,48>> =>
                       <<"±KC92Y0xNmWr5ocMlK6tGhUPm0ook536v/cqXBwKp2t4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,98,102,54,56,51,101,100,
                     45,100,53,54,49,45,52,54,48,49,45,56,48,50,55,45,102,97,
                     57,48,56,101,101,48,97,53,57,48>> =>
                       <<"±Dv2uIKiWWztLUqZDGY34P7KKiJkSoB+gpesL1DP1W1U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,52,50,55,97,100,52,53,
                     45,98,54,102,54,45,52,53,100,57,45,57,50,101,56,45,102,
                     102,56,97,54,49,48,97,97,53,51,48>> =>
                       <<"±j2WoCOKuAlm5JtvXxsH4OijKJFJTMDWW2lzqFknsasc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,50,56,49,51,54,55,45,
                     98,98,57,102,45,52,56,97,50,45,57,49,50,101,45,51,52,56,
                     97,99,55,50,97,97,48,99,100>> =>
                       <<"±amZSxFHiPI5Tb3dXnCjlvOhYWLtw3WvxdITTqWKJYbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,53,100,97,97,100,97,
                     45,100,57,102,52,45,52,57,100,52,45,57,57,52,49,45,54,
                     49,102,50,99,56,57,55,55,53,49,101>> =>
                       <<"±62vabEmPj40Q6vjeVZXAml+wA29Ttt40is8PdX9NvBs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,55,101,56,102,48,50,
                     45,56,102,50,98,45,52,102,51,50,45,98,57,57,49,45,97,51,
                     99,55,49,99,52,97,56,97,49,54>> =>
                       <<"±WZt1HZOkoYv3HF14DSX2/S80yvGwLOrfcEgqGmsZxos=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,48,99,56,49,50,50,45,
                     51,98,101,52,45,52,50,54,51,45,97,56,50,102,45,48,53,55,
                     50,48,49,48,97,53,48,97,101>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,54,49,98,56,99,101,51,45,
                     49,54,51,102,45,52,101,52,57,45,97,55,102,49,45,54,48,
                     102,51,99,97,48,53,102,53,53,48>> =>
                       <<"±WoENehLdngh3tnV/JOIurtqa5mUcoRF0CKV/UPQ08t0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,50,54,49,97,54,102,
                     45,57,56,48,99,45,52,55,97,100,45,56,57,56,98,45,102,98,
                     99,53,100,53,54,54,52,97,100,98>> =>
                       <<"±aDja/XMDfJNPtq7aVEAFY27TUCfK/k6RqBPgbAwcKqM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,99,55,97,98,49,48,
                     50,45,57,48,54,54,45,52,102,49,99,45,57,52,102,51,45,55,
                     54,53,52,53,50,51,50,100,100,54,51>> =>
                       <<"±KBtln76wJGKhXKhJWT7Iec/w6l/T2QLoA9E7M0QdCEI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,52,55,100,55,99,
                     55,100,45,98,50,101,100,45,52,55,101,50,45,98,55,54,48,
                     45,51,98,100,101,51,48,97,50,52,51,52,51>> =>
                       <<"±HeFOeXCjR3mHt6enHaF4wLjGfR2QNikDGMK03ANctB0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,53,99,52,101,48,101,
                     45,50,99,102,98,45,52,57,100,53,45,97,52,100,98,45,51,
                     99,50,100,48,97,99,97,48,99,53,57>> =>
                       <<"±BRlLroE743B0npAWeS9jO2RSEor8jOnwofQTCAlVhNI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,55,48,56,100,48,98,55,
                     45,57,99,49,50,45,52,101,48,48,45,56,51,101,102,45,98,
                     99,55,99,56,99,100,56,100,52,99,49>> =>
                       <<"±/1HvujxAiLixlqkoRoKF9egyYVH1kBS9LSHGhG8tl/M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,55,49,52,48,100,54,53,
                     45,98,54,56,49,45,52,56,98,100,45,97,100,51,54,45,102,
                     53,97,99,57,100,54,98,101,49,56,49>> =>
                       <<"±++ymRtE5Je/rSX0QZ8S5wMIK3RW20jIPyQFH3ehEhE8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,51,51,56,54,53,55,102,45,
                     53,52,54,55,45,52,56,57,49,45,97,48,102,52,45,101,100, 
                     102,52,102,102,53,102,52,100,102,97>> =>
                       <<"±Q7xpTa4pYN1kXCkXVQUfkfKKTVpiKDmsJmtSO47IjNA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,99,97,57,56,56,97,45,
                     102,50,50,101,45,52,97,52,52,45,97,56,99,54,45,52,99,53,
                     55,97,52,50,55,102,102,52,52>> =>
                       <<"±7zGmUKyXL+8AseusN5Xq3GFyiIYpTOG7DHLvp6N4E/Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,55,98,97,100,99,52,45,
                     53,101,53,102,45,52,50,56,99,45,98,52,102,50,45,54,49,
                     55,56,98,48,52,54,100,100,102,55>> =>
                       <<"±Kmft2RVCI2iZblcOd+Zau1uQ5AB3Fw5crxR9M06AgYI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,99,49,97,98,51,98,49,45,
                     56,101,102,55,45,52,55,51,57,45,57,50,52,101,45,53,99,
                     56,98,56,55,99,54,55,50,54,49>> =>
                       <<"±CKJnIgogSYN8zX5sUnCidCNRDW7qsWEsLkRU4J//jec=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,97,50,98,98,97,56,45,
                     52,51,52,102,45,52,97,99,55,45,57,97,54,98,45,50,55,54,
                     57,48,102,56,101,48,98,51,55>> =>
                       <<"±eWG61A2f5DxI6xe2fu8lYfpfXg2z9xj+i/8Jd8utqM8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,56,49,56,102,97,51,
                     102,45,99,56,53,50,45,52,49,48,97,45,57,48,97,53,45,56,
                     53,53,54,99,49,48,56,55,101,101,55>> =>
                       <<"±zsWE7rpxhHh3ph9nXshL9VbxgERuRHVFQ0RtaN6uaTA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,56,102,55,99,54,54,99,45,
                     100,51,54,57,45,52,54,56,50,45,56,102,101,51,45,53,55,
                     97,57,50,99,98,54,48,49,101,49>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,56,49,97,53,57,57,56,45,
                     98,99,97,57,45,52,99,52,97,45,97,51,53,49,45,49,56,52,
                     54,52,53,101,57,97,97,48,97>> =>
                       <<"±7nnpZ1XjJJTpFJoIcxyf8J7nngZSffl79iwIgyIGsVY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,48,100,54,54,98,53,99,45,
                     50,56,51,48,45,52,49,50,52,45,98,101,48,97,45,57,55,100,
                     99,49,54,53,48,52,54,49,100>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,99,49,53,48,98,100,45,
                     101,48,52,52,45,52,56,57,55,45,56,101,98,100,45,97,99,
                     49,56,51,101,52,52,99,51,55,57>> =>
                       <<"±uzAALDu3B8xX8Sy/vrOx2DBlUD34MafvFaf2KkLZK6s=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,102,56,53,54,54,57,
                     51,45,57,51,102,99,45,52,52,49,54,45,57,55,55,53,45,97,
                     48,98,57,49,53,49,100,100,53,49,51>> =>
                       <<"±SQWYF930BGDzKlFzglJoqjTug4xUZa0FbZ7BdlEUxeo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,53,49,57,49,97,100,
                     51,45,53,101,51,48,45,52,57,101,101,45,57,51,48,55,45,
                     52,102,98,97,98,54,49,50,56,54,52,102>> =>
                       <<"±1jjznsxz1ObzEPeKRa0hvykct0cIXHabMHzEs0FM1U4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,49,56,51,98,52,101,102,
                     45,52,49,56,49,45,52,52,99,97,45,57,99,53,49,45,54,52,
                     49,97,98,54,56,99,54,52,48,52>> =>
                       <<"±RcvMf3zehXcD0zethksWX72ME/h6vygzdYuPLSs+eXU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,53,54,99,50,100,101,
                     45,54,53,98,57,45,52,98,54,54,45,98,56,51,102,45,57,97,
                     98,55,55,53,99,100,98,52,101,57>> =>
                       <<"±FgFcmNX8T9RgFw7t6nSHC0qikxvUuCPacHgQo2RsHBc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,97,97,98,100,57,52,
                     45,52,50,102,52,45,52,51,56,100,45,97,57,101,102,45,49,
                     101,48,52,49,53,50,50,53,54,99,102>> =>
                       <<"±WaJ9KliY7mQqU4OsDwtyL91ovnrJuJ2WCtu0Jwj+xzU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,99,48,55,52,49,98,
                     102,45,99,48,52,53,45,52,102,53,53,45,98,48,48,48,45,
                     102,97,48,57,99,51,97,49,50,53,55,52>> =>
                       <<"±fG0JjAZM7Ef0rPFDiszY0/XQU1Laj/r6+S8d633fxJs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,54,52,56,97,56,51,49,45,
                     97,102,50,57,45,52,53,51,52,45,57,99,57,51,45,55,56,57,
                     52,100,53,97,101,51,101,101,99>> =>
                       <<"±Dr9gNgF+R4Jm/Id7R7dFCRiTvdeUZdmffhJAxzoHB1M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,101,51,48,97,52,99,100,
                     45,57,57,55,55,45,52,52,50,51,45,57,101,53,48,45,102,97,
                     102,102,102,53,48,97,50,98,48,102>> =>
                       <<"±ktGLzGvsqozyvECEJRwIWzjVfRSuJJcMzS9hCAsOLFY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,56,53,102,53,97,97,54,45,
                     50,101,100,56,45,52,99,97,101,45,56,99,101,52,45,53,49,
                     98,56,50,55,57,56,48,99,53,101>> =>
                       <<"±8QQ1ZIR5T1QAwKCCF1yX7GobdUi2tZghlbZNLWssNts=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,51,99,50,55,102,102,
                     45,53,51,102,56,45,52,52,102,101,45,56,98,56,52,45,56,
                     52,53,52,57,100,102,99,99,99,98,52>> =>
                       <<"±qAU88WsMMGdRWWkJdxnznmfVk/hQTPsbBa0cnKjh6/I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,48,97,55,55,100,50,
                     45,52,48,97,98,45,52,53,99,54,45,97,56,101,49,45,51,53,
                     49,98,48,99,99,51,98,49,98,97>> =>
                       <<"±0g+dbiQafMQdeiqf2pCihcmn3yxYWHA34IxdSpKJ0zM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,55,56,99,53,53,101,
                     45,52,48,56,99,45,52,99,53,54,45,57,57,101,51,45,56,57,
                     101,101,55,57,49,102,54,52,54,56>> =>
                       <<"±AI0a44vrwLdBgqlkDiH0zKDoyqOiVtVcpJxdFsfQPWI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,99,100,51,49,100,
                     53,48,45,49,56,51,56,45,52,53,50,57,45,56,98,55,101,45,
                     56,48,98,102,49,100,54,99,98,100,54,52>> =>
                       <<"±5uVbaptYpWxVFujcljNXGrfw0rJDd5TJGN/MKwTARZw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,101,51,56,52,99,49,
                     98,45,100,50,101,99,45,52,99,55,49,45,98,50,102,102,45,
                     100,101,48,52,54,102,57,48,57,50,54,97>> =>
                       <<"±u/3XHYBHhSY79bIO2nsMWmcFupUZyWiFIqOHDH8x5t4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,101,48,99,99,53,98,52,45,
                     52,53,54,55,45,52,57,102,57,45,97,99,97,100,45,51,99,48,
                     52,48,50,101,52,99,99,100,56>> =>
                       <<"±WFbhV8pQhq4+ktKXqrdp1EcwQ5/2/CQLq51STkL+m6I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,50,54,56,54,54,57,102,45,
                     98,100,54,101,45,52,56,54,101,45,97,57,53,53,45,53,48,
                     48,102,49,51,99,101,97,53,55,97>> =>
                       <<"±wt7jwCsxbV2e8hCcPYmk34x85UwOTPvFg3S+iBUck3s=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,51,50,99,101,50,
                     57,97,45,102,100,52,57,45,52,53,57,49,45,97,98,56,54,45,
                     99,48,101,57,55,98,50,50,51,97,57,56>> =>
                       <<"±BaGsGPj8w4ffC+4E6/N5QFKPV/jTKBoSOVQmX4psQPE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,49,101,57,50,97,55,57,
                     45,55,48,53,97,45,52,53,54,53,45,57,49,100,49,45,48,56,
                     50,100,48,100,97,55,50,102,101,100>> =>
                       <<"±xax1P5mi9x7yOfclc+Gr2BSDRXq4ShSUaZWFz/WSZR0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,98,53,51,99,57,55,102,45,
                     53,48,50,49,45,52,56,54,49,45,57,102,98,48,45,48,55,56,
                     98,99,56,101,102,101,97,55,50>> =>
                       <<"±rewY4UxQo3HbuWwvHKU+RuCzbgbSdYgqjMjSLA0Fc7k=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,52,51,48,100,57,
                     51,55,45,56,54,53,48,45,52,51,50,53,45,98,48,55,52,45,
                     97,55,97,55,49,100,99,53,101,57,53,56>> =>
                       <<"±hk3ChXYTqo/rlSDSdX76K3vPTXpook7tT6N+7YyhYW8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,48,48,55,53,101,48,45,
                     49,50,102,99,45,52,54,56,52,45,57,57,98,49,45,55,102,53,
                     100,48,101,102,53,49,48,49,54>> =>
                       <<"±KYueEC/w9WjkJp+Dls1z9xuqYXPVrpdfjk/CzPl1+xM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,55,55,100,99,100,56,51,
                     45,57,102,49,57,45,52,100,48,99,45,98,49,99,100,45,49,
                     48,56,55,52,57,101,50,52,102,102,101>> => 
                       <<"±zaFexzRMqdNKmoxO08IPTKY4gXs/OjBLyJ6U6ACEYSE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,50,52,50,53,56,57,45,
                     53,99,98,99,45,52,54,52,49,45,97,51,49,101,45,50,49,49,
                     49,54,53,57,101,52,54,55,54>> =>
                       <<"±EvFcAgUiYCLyJ3rV3YsWkXBcICeQeWT3kkC7nm9Dvcc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,102,49,57,101,98,99,57,
                     45,49,54,51,50,45,52,48,102,98,45,56,48,54,102,45,99,99,
                     101,54,55,56,52,98,51,97,53,97>> =>
                       <<"±+MCo6esgAzzWZxbQ2RmgWIORE3rtjwxThhvaZdVZMQQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,98,57,50,53,55,54,45,
                     53,57,97,48,45,52,99,51,56,45,56,51,55,100,45,98,49,49,
                     101,98,102,101,49,53,101,97,52>> =>
                       <<"±aLpeFowIwTU+65bemmjXdIkdojsGVJVv5ntztyWYGhE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,49,97,56,101,99,97,48,45,
                     48,51,54,48,45,52,56,100,52,45,98,49,49,50,45,57,97,102,
                     57,102,51,54,97,57,100,52,97>> =>
                       <<"±rWZTDLHTmNEk5uJUx2KvPP1gJhHBCJkTU8m+WdGfn94=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,49,54,50,53,53,52,101,45,
                     54,97,55,97,45,52,52,54,52,45,57,48,97,48,45,101,102,
                     100,52,49,98,52,101,50,53,50,55>> =>
                       <<"±O07uaZauuR0WBC5hEHSyn1K5Fa51VdTZEqjmEfn5q+g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,50,98,102,55,50,55,
                     45,102,54,57,55,45,52,99,99,97,45,57,50,55,98,45,49,51,
                     51,55,49,52,100,102,50,54,51,50>> =>
                       <<"±Ww2wjY/2Zw7d1cYAiFiKKd9pju8eco0asMB/tsqCk2Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,53,54,49,57,53,51,45,
                     100,98,99,99,45,52,101,102,102,45,98,51,102,101,45,52,
                     54,48,57,98,49,51,55,99,55,51,55>> =>
                       <<"±AitG09XJQrHPJpPIcML9bnQlq8MNbgEo5Khuu/jciK0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,97,102,100,53,55,
                     100,50,45,54,54,53,56,45,52,51,99,48,45,98,97,50,51,45,
                     98,54,48,52,49,51,50,48,56,53,99,100>> =>
                       <<"±7vnFsxbnhAw5gtA+bL42MAqQktRgrHciJ1GDy/tXd+s=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,54,52,57,52,101,54,
                     99,45,51,55,102,99,45,52,57,102,52,45,97,98,51,100,45,
                     55,54,53,99,99,54,101,48,55,57,48,57>> =>
                       <<"±zd+6aNoDHBaN78/q3bGu+RBjN7zv0u60UtV8iwagAhw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,99,99,50,52,101,101,
                     45,49,53,55,56,45,52,53,51,50,45,57,99,100,51,45,53,57,
                     100,50,100,48,101,100,100,54,54,49>> =>
                       <<"±YZLvOToPK8mATDG7DjbK3aBUun+QZWAsJELJZOKNlZ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,49,57,55,101,53,98,52,45,
                     52,50,99,49,45,52,54,53,53,45,97,48,53,97,45,52,55,57,
                     52,99,100,48,56,102,55,98,57>> =>
                       <<"±TYP6X6WfaYmQcQ+jqIF+PfB3N5YbF1PpSkg3saQbCEI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,100,53,53,54,56,55,102,
                     45,50,56,52,102,45,52,97,102,100,45,56,99,53,98,45,56,
                     57,97,56,48,56,97,57,99,98,50,97>> =>
                       <<"±rsv+J+bg6VdwfVCRvbuoIvSfhRYm9Wgq9p3DtjTw2yU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,55,101,99,101,57,100,49,
                     45,51,55,57,102,45,52,48,97,50,45,97,97,57,52,45,102,50,
                     54,100,55,57,57,57,54,52,56,101>> =>
                       <<"±EvJhz0CiLvlzWG6YyYkDRVTxswrpb7FdigIS2LR29Sg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,98,99,98,99,50,56,45,
                     56,52,51,100,45,52,53,51,101,45,57,99,52,97,45,55,56,55,
                     100,54,49,101,57,52,101,52,102>> =>
                       <<"±OAnl9oRKHc4Sv9uG4IK1+V62Xt35QXayHXMG5hxbuP0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,98,97,55,98,49,56,
                     97,45,52,48,49,52,45,52,100,52,49,45,56,49,54,101,45,56,
                     98,49,50,50,48,51,52,48,53,56,98>> =>
                       <<"±q7BPhPon4swCMTLbSXzv8UnXCKsIzfxlahrkljb0diE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,48,48,97,97,102,57,49,45,
                     52,56,98,102,45,52,101,48,99,45,97,56,53,99,45,53,99,54,
                     97,51,97,98,52,53,52,55,101>> =>
                       <<"±tkC8qA4/U5mAJET4J3QyMGCoQsC4oXB1/dq/wZJmWv0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,53,101,49,54,98,55,
                     53,45,55,55,51,54,45,52,98,99,100,45,56,97,100,101,45,
                     51,49,53,49,54,102,50,53,97,98,51,55>> =>
                       <<"±d9CylzjGXbbQMgg6PWYMF/528+bQu5c+S8HF1Grr+FQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,56,55,101,98,52,51,45,
                     100,51,50,101,45,52,102,48,99,45,56,102,51,97,45,101,56,
                     99,50,56,53,54,55,98,102,100,51>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,56,53,57,56,49,102,45,
                     99,56,55,48,45,52,101,57,56,45,56,102,51,50,45,49,51,
                     100,97,53,49,98,52,99,49,101,52>> =>
                       <<"±8bapf5stvNhI96Y398ush5jCEWB33cU9ISPlssNbmak=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,54,50,55,51,54,49,45,
                     54,55,99,50,45,52,51,50,53,45,97,57,56,97,45,101,48,57,
                     50,97,49,50,48,54,102,49,48>> =>
                       <<"±tIRVzgjvCVYx178neRo39Sqw6ks5WCYzy5QYIGtjPmw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,52,100,51,98,53,56,98,45,
                     54,97,53,55,45,52,98,49,101,45,56,53,50,54,45,101,52,49,
                     97,56,50,53,51,50,101,54,98>> =>
                       <<"±vEM3RYk/m6QS5UusgxnFuPotmc79ssjYKDBrukWjc/A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,55,52,48,97,53,55,45,
                     100,52,56,53,45,52,49,98,54,45,97,54,57,49,45,51,48,98,
                     99,101,49,48,102,49,50,99,98>> =>
                       <<"±Qh9htRpCPhOS1mtthiMnoCVJlTyq+5RBjKmMbDUzV4E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,97,50,56,102,55,57,50,45,
                     54,57,52,98,45,52,98,50,99,45,98,56,99,99,45,100,51,102,
                     57,100,48,98,102,102,57,48,102>> =>
                       <<"±bjYr/RoUbbrhfw3FMxf6n1ZFUNMwwb556MriazJFbGs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,100,54,49,53,54,51,45,
                     57,54,100,49,45,52,54,98,97,45,56,49,101,51,45,102,55,
                     52,97,52,48,55,97,57,100,97,50>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,102,49,53,54,54,57,48,45,
                     55,56,57,98,45,52,52,55,53,45,56,97,50,97,45,101,54,100,
                     54,100,50,50,52,51,100,51,102>> =>
                       <<"±IN6M6dGfX8T2k2qbvpaSuZmQhqsW39pt663cW4LSQdc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,53,97,100,57,53,55,101,
                     45,49,51,101,98,45,52,52,49,100,45,98,99,102,55,45,53,
                     54,52,98,102,98,52,100,49,52,55,101>> =>
                       <<"±J9Oi7tXXDVnrgfRJ72meyc25+ozqmJd+OaDPORxAoA4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,53,99,102,97,57,99,55,45,
                     51,57,102,50,45,52,52,101,101,45,57,99,57,99,45,49,52,
                     49,101,54,102,102,54,57,50,57,48>> =>
                       <<"±YkTmSxnmIXL6qH1FD+edgelwQqhKQWo6pPzZ+mJJrqI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,57,48,102,102,99,53,
                     45,52,48,55,49,45,52,99,55,50,45,98,50,56,54,45,55,101,
                     101,50,56,98,57,98,101,51,52,48>> =>
                       <<"±mRvqM/+GBYxmNKDYh8JrP4kNEQyV3gOMhiH1TBlC/o4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,53,97,55,50,49,57,45,
                     53,56,56,57,45,52,51,52,101,45,97,101,50,55,45,55,57,
                     100,56,57,97,100,100,99,56,55,102>> =>
                       <<"±yfGQx9GWl4EWwWekqG7FxChlOQxzn6HEp2drVJoKYRo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,49,57,51,57,99,49,
                     55,45,101,50,57,100,45,52,48,57,97,45,97,102,51,98,45,
                     56,53,51,99,102,57,98,48,99,101,101,99>> =>
                       <<"±wU8bsRpdhBM3QzybVh4bxyfCFWbMmiEuKg6KxYb0CgQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,53,53,102,98,102,49,
                     45,53,54,100,98,45,52,98,98,57,45,57,56,55,51,45,53,101,
                     52,99,50,49,100,56,50,97,48,98>> =>
                       <<"±j+7jRMk0cQNfd5lbc4RGfiQAqIsF6/RM3cs9z8+AW/I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,54,48,53,99,102,99,
                     45,102,99,52,48,45,52,100,57,52,45,98,50,48,51,45,50,55,
                     57,56,48,55,101,98,55,55,48,101>> =>
                       <<"±zMq860HQHKHlTuOjCkUn2+bS6cmAvs/gycCmUPylEwc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,53,53,98,97,97,
                     102,97,45,52,49,101,57,45,52,51,53,49,45,57,57,101,57,
                     45,53,53,97,55,100,49,50,55,101,102,57,48>> =>
                       <<"±la5+s7TfTZbebksm9OehKeo6f5x7QbJ/J8+MvvXER1c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,49,98,50,100,50,97,45,
                     49,56,50,50,45,52,100,55,98,45,97,50,51,56,45,55,100,55,
                     102,101,99,51,56,99,50,100,57>> =>
                       <<"±jVV1WlTH2mfagUuPwRd11hIHjlUrpHGOEfC9IKZwsmo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,56,97,99,53,53,98,
                     45,101,101,49,102,45,52,57,57,54,45,57,49,52,102,45,50,
                     100,100,101,49,50,54,48,49,51,50,49>> =>
                       <<"±nvQouN4fb4f3Pv4olLi77SwrghCEgr2yUtjEd/bmJAM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,98,52,52,100,55,98,
                     102,45,48,48,99,98,45,52,97,100,50,45,57,101,99,101,45,
                     49,55,54,51,101,55,55,53,57,100,55,101>> =>
                       <<"±VfL8GH0RFhL97idsL3GqA6oKYpV6z3uv9Fy3YwJN94w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,50,49,57,55,102,56,45,
                     97,56,54,54,45,52,48,101,98,45,57,49,100,54,45,102,51,
                     99,97,98,51,48,97,99,56,101,101>> =>
                       <<"±1VlLHv4oWk6ciyBvUIjHpFb12MOXzDj5G914Kbd12jE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,57,55,97,102,51,53,98,
                     45,56,48,54,101,45,52,53,100,57,45,56,50,100,97,45,56,
                     101,50,55,51,100,100,100,55,49,50,51>> =>
                       <<"±IiX2L4Bak+k7TH1RHkxjSn8tjzBTss/SCl8AWz3sloE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,56,52,57,98,102,50,45,
                     101,102,54,49,45,52,98,101,57,45,98,57,48,51,45,50,55,
                     48,49,102,50,97,55,56,53,100,54>> =>
                       <<"±jVLOMDXPKdGMqMhvLk/z5vgmxj9MTGgP+xa3y/7qyvU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,55,55,57,101,55,54,99,45,
                     55,101,100,57,45,52,57,101,100,45,57,97,101,51,45,100,
                     97,102,101,54,99,99,55,99,51,101,101>> =>
                       <<"±zl9I7iOfSFODvHctWqo9o8gqbMTrZlqUeydS6XD1lTA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,48,98,98,98,101,50,
                     55,45,57,52,50,98,45,52,99,99,52,45,56,102,51,97,45,100,
                     49,49,99,98,98,52,55,54,51,100,99>> =>
                       <<"±qtdPgGprnXunMBcb+f4IYyh/uPYI19XtykOkDVSdEms=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,51,57,54,55,49,56,45,
                     51,54,55,54,45,52,101,100,98,45,57,53,97,56,45,48,48,97,
                     51,53,50,97,54,98,57,50,101>> =>
                       <<"±aYiU86xQZUPBEGdhca8MKi6hfxfL0rS7M1LBSXTYHVw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,97,98,52,48,56,100,
                     55,45,98,97,51,102,45,52,99,51,99,45,57,57,99,52,45,50,
                     98,97,50,55,101,51,50,51,52,100,102>> =>
                       <<"±F7BtsxYAr69sx7VcDc+QEBgVKs+mz248Q0Zju+KJhxM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,100,101,55,50,56,53,54,
                     45,57,97,101,56,45,52,99,51,97,45,98,52,53,97,45,100,50,
                     97,51,101,101,57,101,53,50,49,50>> =>
                       <<"±PYib1yALideqmqwAYphM+CR6JJxIfPrtan3NMwYxwOw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,52,53,55,100,52,50,45,
                     101,48,54,50,45,52,97,100,50,45,56,49,56,97,45,100,102,
                     48,53,57,53,99,102,101,50,100,49>> =>
                       <<"±XXcZqGgW277urOzSwTuamzYs9LAeXGD2RYQZP0OJCXw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,54,50,98,55,97,54,45,
                     97,57,98,50,45,52,56,55,51,45,56,100,55,97,45,56,100,53,
                     97,97,54,54,57,49,48,57,50>> =>
                       <<"±HxJXCMb8AE5zwqBwTaoBMagAQN/XlTEZ+eYu/3b/N10=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,55,53,100,54,97,53,
                     45,49,97,100,53,45,52,53,53,102,45,97,49,57,102,45,56,
                     50,97,102,56,57,52,55,100,99,48,102>> =>
                       <<"±lJg8YrjZY71G9GdC35PA/g067RqWSP1/EW13UGMo/K4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,49,102,99,100,101,48,
                     45,55,51,56,48,45,52,51,54,51,45,56,56,57,97,45,52,98,
                     100,52,51,100,50,98,97,51,55,98>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,100,99,100,49,49,54,101,
                     45,53,57,57,51,45,52,100,50,52,45,97,52,56,54,45,102,
                     100,101,51,53,49,100,55,57,55,53,56>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,102,100,54,100,102,50,
                     45,100,97,50,53,45,52,101,101,52,45,56,48,99,48,45,100,
                     50,52,53,54,52,57,49,52,54,49,54>> =>
                       <<"±c+OxLRLbW2eVujXnfUm8qRbx2KwKAtd0LXvrhjYQfuk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,97,101,55,101,53,55,56,
                     45,54,48,49,53,45,52,100,52,98,45,56,101,56,102,45,48,
                     49,98,54,97,54,50,102,98,97,51,57>> =>
                       <<"±WTJ/GTmA7yKSNxBX/O37z4w7WZP2Qs5weh9v7FnwUIY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,54,50,54,99,55,100,
                     45,102,97,99,48,45,52,53,57,54,45,57,49,97,101,45,48,
                     102,101,57,97,99,51,99,102,50,52,99>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,100,48,102,52,48,
                     49,57,45,97,97,51,55,45,52,49,98,101,45,56,52,100,52,45,
                     52,54,100,98,57,101,52,50,51,57,100,98>> =>
                       <<"±rlGrXfpRkxnKOPbx2ujFXn9t0oKFkaT5VL95f/88iqE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,98,101,49,98,97,100,97,
                     45,57,101,52,52,45,52,55,100,50,45,97,57,54,48,45,101,
                     102,49,50,98,50,56,48,54,56,52,97>> =>
                       <<"±F/riQjQMukZuzfIkCL354yDncqu0p7LmsjtdEhqACo0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,101,52,55,57,49,98,100,
                     45,53,52,53,52,45,52,54,50,97,45,98,55,51,50,45,52,100,
                     51,53,52,101,55,102,55,99,57,102>> =>
                       <<"±Y6dlNF6BiSOSbdVS+lwnfQfeLsgfYwD5QQlffw+6iWI=">>, 
                   <<1,0,0,0,0,161,98,109,116,95,53,50,57,48,54,99,53,48,45,
                     48,54,52,54,45,52,97,57,55,45,57,51,52,48,45,97,98,57,
                     53,99,50,51,49,52,53,48,51>> =>
                       <<"±VvFKE7HiKoxhmDbPRYTCvYJo1/7hoY0CyZWE7tTjGyU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,51,55,97,97,56,52,45,
                     50,53,53,48,45,52,98,49,57,45,98,51,50,57,45,56,48,100,
                     50,101,52,55,99,55,100,56,55>> =>
                       <<"±1uGXhDiXyQUddphID8RyMTAgTM3duVthTEBgQPeeJcA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,53,56,54,52,102,54,45,
                     102,102,53,49,45,52,54,50,48,45,57,99,53,48,45,51,102,
                     52,54,52,101,99,57,56,54,102,48>> =>
                       <<"±DptLHSeDmjHDOrK2o468qwTCylXOBOkPZJeT2mB5Zyo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,53,50,50,49,50,97,54,45,
                     54,99,101,49,45,52,53,97,99,45,98,54,57,97,45,53,101,
                     101,97,51,100,101,100,98,99,101,102>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,54,54,54,53,101,102,
                     45,51,53,48,56,45,52,98,102,97,45,56,53,56,57,45,50,99,
                     53,48,51,55,55,52,57,97,98,102>> =>
                       <<"±XaoRa8en7+x5KVPuU92XhZicErqAc9oGK6+Cd9fQRZA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,54,98,98,51,102,48,45,
                     100,54,55,50,45,52,55,99,56,45,97,54,55,48,45,50,49,97,
                     50,52,52,48,98,102,101,50,55>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,49,52,55,100,102,
                     52,102,45,48,56,97,54,45,52,101,49,98,45,57,57,49,50,45,
                     56,102,56,54,49,56,54,51,56,100,55,98>> =>
                       <<"±syc4z0fXPUo7XZThY+avQT5Os01Ks4nz6We2o32ky9g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,51,50,54,57,102,56,56,45,
                     53,53,100,56,45,52,53,53,50,45,56,48,102,48,45,100,57,
                     97,54,102,57,57,48,56,97,51,49>> =>
                       <<"±ul7315Vg8IDH/TxE9oT4d4t9RcdvtwD571gNQGdBdzc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,100,49,51,56,99,98,
                     56,45,100,101,57,99,45,52,56,56,52,45,57,55,57,54,45,
                     102,56,52,101,54,56,56,51,52,48,57,50>> =>
                       <<"±0HVtbW6RCZGTFJHoqjHKHjFl0AGgyI4mLg6TprBYfk0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,55,98,55,54,101,100,57,
                     45,102,56,99,102,45,52,53,97,57,45,57,57,98,57,45,57,49,
                     48,55,57,48,53,54,102,100,55,55>> =>
                       <<"±go5QNV7f6r05m7UswOSFNV19cjDMNZNhp9akdzxB2qE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,55,52,52,52,50,54,
                     52,45,53,51,54,48,45,52,101,52,101,45,97,56,101,100,45,
                     48,98,57,52,97,53,101,97,51,57,53,55>> =>
                       <<"±cQRnQ4lkt+/8Ep7NI9J2qX7YXkX7xpJ3J2m4tMnICOk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,98,54,54,97,52,51,48,45,
                     101,51,54,102,45,52,102,52,57,45,98,51,50,52,45,56,56,
                     49,51,56,101,102,48,55,54,102,50>> =>
                       <<"±BF4I4+/HdLEEOHPgg3yrIkdEP1JHs8u1u0IC+MWFrgA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,101,55,50,102,54,48,56,
                     45,52,54,51,48,45,52,56,54,102,45,57,55,99,99,45,55,51,
                     48,56,55,99,54,99,52,98,101,57>> =>
                       <<"±1B9eqimoaIlWxPmqmBuOtsGCVwXHbSIBBqe2WawDVzk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,102,99,99,52,52,57,100,
                     45,54,49,50,100,45,52,57,100,55,45,97,50,102,102,45,100,
                     54,100,102,48,51,97,56,98,48,97,100>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,54,101,51,101,53,97,
                     45,97,100,50,51,45,52,54,99,97,45,56,100,100,48,45,55,
                     50,50,99,97,49,57,50,49,99,54,99>> =>
                       <<"±3bpUmrRESqXZvZYojiS5GwlSbnATuuPjGu8vhO4Knl8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,55,100,102,51,50,51,54,
                     45,102,49,53,97,45,52,50,51,48,45,97,50,100,100,45,49,
                     54,52,50,57,57,102,51,98,49,48,50>> =>
                       <<"±M6nACTPfspCA9SdcnrrshB3Z52X6VAJIqPRMaXHjYXQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,51,99,98,53,57,98,
                     97,45,97,49,102,97,45,52,55,102,51,45,57,53,54,49,45,
                     101,102,97,100,54,49,51,99,54,52,54,49>> =>
                       <<"±jpvurXjL3bSuwv4I6aFYMWuBj1W308QW5DWz6N5bGTw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,101,101,51,48,55,
                     102,100,45,98,98,101,55,45,52,56,53,102,45,98,101,57,50,
                     45,55,98,50,54,56,97,100,98,49,55,48,102>> =>
                       <<"±LQKmz4YYu/+4/CKaoB+tSsfqL5hLfAdnYc8x/UvRhfY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,49,54,57,102,57,102,
                     45,50,97,55,101,45,52,57,101,48,45,56,98,48,48,45,97,98,
                     57,48,102,101,56,57,101,52,54,52>> =>
                       <<"±GaLTEorTcOIKYAG9LxmqkrMfxmvwSjLQvU7piv2qElk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,101,48,55,55,50,99,
                     57,45,55,101,100,101,45,52,97,102,54,45,56,51,50,54,45,
                     101,55,99,102,97,101,55,49,50,57,56,49>> =>
                       <<"±L/a9tuZwIt80YQQkk1gsf19i4g1ph1g03Tx3xKBc4F0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,50,57,57,49,56,102,45,
                     48,56,100,52,45,52,100,49,54,45,97,100,51,48,45,99,54,
                     57,99,49,49,100,52,53,50,55,100>> =>
                       <<"±DRKZEO0nspSsukBPOFh8PBa91idYJT2aI8ODbui3ovc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,99,56,48,98,54,98,97,45,
                     98,56,55,99,45,52,56,57,51,45,98,57,48,52,45,55,97,56,
                     55,52,102,54,50,49,49,49,101>> =>
                       <<"±mbZPpBGbBgZGB53RM27XykzvmhUcwQKiSskP9ebkcfM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,55,98,55,56,101,101,53,
                     45,102,99,102,53,45,52,54,57,52,45,56,49,97,49,45,100,
                     100,100,56,55,55,48,98,56,50,48,55>> =>
                       <<"±+bW6o+SJ7peodm32wlnJhf8n2kxidGx3yJxA2yZXuk8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,51,52,99,51,97,54,
                     57,45,53,57,100,53,45,52,101,56,53,45,98,101,97,99,45,
                     100,49,48,55,50,101,55,97,52,101,50,48>> =>
                       <<"±Hp9Jz3+MYncODqqVdlMAGpjxlwD3xJwzLQ0PgKgioRU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,52,50,101,100,101,55,
                     45,57,98,99,49,45,52,53,102,57,45,97,53,50,99,45,98,97,
                     101,97,48,50,51,52,49,50,102,99>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,52,53,52,102,102,52,48,
                     45,55,51,98,55,45,52,50,52,56,45,57,56,48,56,45,98,102,
                     49,50,54,52,57,97,97,54,100,100>> =>
                       <<"±+lEZlXvRd3KWpFv/LA+WVYse/mZvMarZaIuVNzHGcuw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,98,56,99,102,53,98,45,
                     100,98,50,56,45,52,53,100,57,45,56,53,99,98,45,53,101,
                     50,54,56,49,57,52,97,98,99,51>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,97,52,97,99,97,49,45,
                     52,98,53,55,45,52,50,98,49,45,98,48,51,54,45,52,97,98,
                     54,57,52,52,49,49,51,48,50>> =>
                       <<"±S5YlL6ocb8o56HnUcGOHhFtnI7mFtwYfSpTnAv4gOKg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,100,51,51,52,50,98,52,45,
                     55,51,99,54,45,52,51,101,50,45,98,55,53,53,45,57,53,49,
                     99,97,53,50,56,54,55,101,55>> =>
                       <<"±KYXTX1jk0e5bQ9M06n0E2p355oijlKS/WHPQjoit+s0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,98,57,52,50,57,54,45,
                     99,54,54,57,45,52,57,52,97,45,98,98,52,101,45,102,52,57,
                     52,97,55,101,51,52,97,100,53>> =>
                       <<"±LbwwYYnmMOeF/b77G0b/+IVsuhfJQzdjcrtbGsUgadw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,51,98,101,50,48,100,97,
                     45,102,57,102,52,45,52,102,51,53,45,98,55,50,100,45,49,
                     54,101,102,52,48,48,56,57,98,53,56>> =>
                       <<"±kQJbLuKYgDOeHNVdB6bvAHp2aqA0MtQ4ZjZt9ecGSyo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,49,99,49,48,55,99,53,45,
                     100,56,100,56,45,52,98,102,101,45,98,48,101,50,45,101,
                     100,56,97,98,52,53,99,52,52,53,52>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,50,102,50,97,99,98,
                     45,54,98,50,55,45,52,55,53,102,45,57,57,48,48,45,97,102,
                     55,49,102,50,57,55,49,48,55,101>> =>
                       <<"±bx1NluWITAhuq/L6x4Yv0OOGUkWljGhX/NCqFL3b3Yk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,51,53,98,98,98,99,45,
                     54,53,97,48,45,52,50,55,49,45,97,100,53,54,45,48,53,101,
                     97,57,99,99,49,100,51,53,97>> =>
                       <<"±rBT0JKwRDpG2XohwFJjRnXqXa3GXJhQYg+x9fDHG+wg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,101,48,55,54,100,102,
                     45,50,48,49,52,45,52,99,51,53,45,56,51,56,100,45,100,97,
                     49,50,101,55,53,49,97,49,48,101>> =>
                       <<"±uUBDbYDH53AO4H4bW03jy02eEQslh5iPfNY/Er1/LXg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,99,49,51,55,57,48,49,45,
                     100,101,100,53,45,52,56,98,101,45,98,48,99,102,45,53,54,
                     101,100,56,50,57,51,101,56,100,56>> =>
                       <<"±dF5sjZQM/pMlQMpZUW8N4Jd+nKe7bmdmjX1x2VCkaLA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,53,55,99,49,51,102,
                     99,45,54,48,56,53,45,52,53,102,53,45,56,102,100,99,45,
                     100,53,99,100,97,51,101,54,102,97,99,55>> =>
                       <<"±GB58UMfc1f/572T7+/5wFZ+Z2viANQ4zu/RkY71m450=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,97,98,50,55,53,51,45,
                     98,52,102,50,45,52,49,53,55,45,97,54,98,54,45,54,57,102,
                     55,48,48,100,99,56,102,52,48>> =>
                       <<"±pPspPB+i01nNQIRGEEIQl+51cyqF19Tx8Dii/cObV0g=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,52,98,51,51,101,
                     98,101,45,51,50,51,53,45,52,50,55,52,45,56,51,100,51,45,
                     51,53,56,102,48,100,57,99,99,98,98,55>> =>
                       <<"±7PEnnsrYGYkhZIGu1sDnwamL/+/FeI3jFMCYlv1YUa4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,55,99,56,102,97,52,49,45,
                     49,102,97,55,45,52,50,52,97,45,56,56,54,55,45,51,100,57,
                     49,57,100,98,56,57,56,56,51>> =>
                       <<"±6rhsGmNnLVZLpexD2wUPAIqqTV5Y54fnp4FnKTtisu4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,100,98,50,102,100,49,
                     45,102,48,56,48,45,52,50,55,97,45,56,56,56,99,45,102,
                     102,49,99,48,102,54,54,48,100,57,56>> =>
                       <<"±wLjasyb9q34aDtHWkx6XQnpq7aWtBD+Uhv9FABU8CUQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,57,56,54,55,57,97,56,45,
                     48,53,54,55,45,52,102,101,51,45,98,57,56,56,45,52,48,
                     100,98,48,100,53,51,57,53,98,99>> =>
                       <<"±irGZBdrCK5asjsgK8se8sHnYITghZYFNDVOy6eyJkOY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,55,49,48,49,49,52,50,45,
                     53,53,56,101,45,52,53,53,98,45,56,55,52,101,45,53,48,49,
                     49,54,54,49,101,54,99,50,52>> =>
                       <<"±HbxudFP9Jx+3YHV2wME+dYLaS4UAn2isEEXTdAk/Gic=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,100,97,55,56,51,57,
                     51,45,97,100,48,49,45,52,102,50,48,45,57,99,48,48,45,
                     102,49,55,98,51,101,56,98,99,57,54,52>> =>
                       <<"±j6Kb5izUMYyn9iqnUXJgN/NcX3guDanjNlwKeo8NiSk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,55,98,53,102,98,98,
                     45,53,99,98,51,45,52,52,54,56,45,97,97,53,55,45,98,49,
                     53,98,50,52,101,100,54,101,49,54>> =>
                       <<"±byvN4q+wa9fFd5Wq1VaYVIAuISrZMFQQlUvd6F0z1D4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,101,57,54,100,99,52,54,
                     45,102,97,55,52,45,52,51,100,57,45,57,101,54,98,45,50,
                     55,56,50,100,102,100,49,53,50,48,52>> =>
                       <<"±Otn4LL7K0tZ7UWiZYTPC0QgtxEB05fOqnFIFI5BvEuk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,54,102,97,50,48,98,
                     45,50,56,51,98,45,52,57,51,56,45,56,102,101,50,45,49,
                     100,57,98,54,57,51,100,100,99,48,97>> =>
                       <<"±vKsRfLWnqvblZBeKmjrHB/Cbg38mqQGMqw1nlY5SNKk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,54,50,52,51,99,57,102,45,
                     53,54,56,49,45,52,56,99,101,45,57,102,102,100,45,102,55,
                     49,102,100,102,57,101,53,52,50,97>> =>
                       <<"±R5IIjE6O3o+k1xmDGvdPI4Uq6EJt05OjI28NefjnNSU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,53,50,98,99,99,54,57,45,
                     100,55,54,99,45,52,52,56,101,45,98,97,98,52,45,100,56,
                     53,97,51,57,102,51,97,51,49,52>> =>
                       <<"±0JgvlGm4KSUzMBKWIHpm292FW/0yv7JliOgZtwoUC9A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,56,98,57,49,102,100,101,
                     45,50,100,57,54,45,52,52,53,51,45,97,54,48,48,45,49,56,
                     53,53,56,99,48,48,99,48,50,55>> =>
                       <<"±VPoeURcMWBjM8X9850YSrNivPG1jlJJNh2hmzwzJQ48=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,51,98,56,50,54,51,45,
                     50,50,97,48,45,52,57,101,98,45,56,55,53,100,45,57,49,98,
                     54,50,98,97,56,57,100,56,101>> =>
                       <<"±gqOlUvGQSx2cJWdoQ3a0c3pFqHpRu68vqdGvPdsVBgA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,52,56,48,57,98,56,101,45,
                     49,102,99,55,45,52,101,98,55,45,98,97,57,102,45,49,52,
                     99,53,52,57,55,52,57,54,56,48>> =>
                       <<"±Fnub5k/mYcFtK5XOPi7EeV8bg74AfmZxUIGG5pMAiio=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,100,53,51,50,48,102,
                     45,54,98,57,55,45,52,48,50,57,45,57,101,56,56,45,97,53,
                     100,49,51,50,97,55,56,56,56,100>> =>
                       <<"±0QmJqvb1tZ+NSTrV4bcOP8cgn/MschzNQ0NemrBd7Rw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,101,51,52,54,101,52,
                     45,51,100,55,54,45,52,50,99,48,45,98,57,57,54,45,100,48,
                     101,49,98,102,102,97,100,48,54,99>> =>
                       <<"±3jqBe0r6WqMFJxRySPk7YyGH3j+sW9SHjsUMsFXCCCg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,54,55,53,49,56,100,99,45,
                     48,101,51,55,45,52,53,48,53,45,56,49,100,98,45,97,48,
                     102,57,100,51,100,49,53,52,54,98>> =>
                       <<"±pa6t7oh5YvY3ahQP18E6TIKe60tYP058cDIdZApsN3w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,55,48,56,54,99,56,45,
                     54,57,99,97,45,52,99,97,50,45,56,57,52,101,45,54,50,48,
                     52,99,55,97,52,100,97,50,50>> =>
                       <<"±g4P+KhdHlGXRfc5cVH+C8z9FD1U0eFIXtmh1JXkKEkY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,101,48,55,98,53,102,
                     45,56,99,97,100,45,52,52,51,54,45,57,50,53,57,45,49,98,
                     97,54,98,101,48,100,52,51,54,51>> =>
                       <<"±guYhSvp53ysrt9C9aFQUE/x8LtNHWd3gXuLksXf73yE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,50,52,55,101,55,101,
                     45,97,57,57,55,45,52,55,54,57,45,98,97,100,55,45,54,57,
                     53,48,101,102,100,100,53,53,56,48>> =>
                       <<"±WQ+78Dp3KyM42Zg54ehnMQygxcil1B5FfG+Yg7O7MLA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,97,102,48,56,54,101,55,
                     45,56,97,50,49,45,52,51,98,52,45,98,50,48,56,45,53,99,
                     97,100,102,99,55,49,56,100,99,98>> =>
                       <<"±mD+h5YUSYpaypGBndHBK5gFGT/3YMz+AA2cbHaNr+G0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,97,51,51,101,52,54,45,
                     56,54,100,101,45,52,48,54,52,45,57,49,50,51,45,55,53,51,
                     48,55,49,55,51,49,99,53,51>> =>
                       <<"±zNOhRj8rE/ktGe3pjwXuzmySBJOKrAoCpa0vn9tiJKo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,97,55,97,56,52,52,98,45,
                     48,50,52,99,45,52,55,50,50,45,56,51,98,97,45,98,98,50,
                     98,54,53,53,102,55,97,97,99>> =>
                       <<"±MtSxM6KLmb0EyHVpHIIbYV1H555uCcYPLofD7fPwPBs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,99,52,50,48,51,54,51,45,
                     57,99,100,51,45,52,57,102,49,45,57,97,101,53,45,102,102,
                     99,53,102,55,50,99,51,56,51,100>> =>
                       <<"±mnMoJsBl7h2WHjQyBrMvrlPeI3tno0/kr9wK4NQ50jU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,99,52,49,49,48,55,57,45,
                     53,50,49,49,45,52,57,52,53,45,98,53,98,48,45,99,52,48,
                     99,98,55,52,50,54,48,49,54>> =>
                       <<"±kU2B9rYIWKnub+WFqfPYrBVY/GWeI4zQS38QyRv1UYE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,57,49,48,53,48,97,101,45,
                     55,100,57,98,45,52,52,49,100,45,56,99,48,49,45,54,56,99,
                     49,53,98,101,97,52,52,53,54>> =>
                       <<"±GmcEFIjaAyAU/7FVWoPTVAACMYb5jR3+/3DHtLuCLUY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,57,53,98,51,50,49,45,
                     100,48,101,101,45,52,55,49,101,45,56,53,97,101,45,48,51,
                     57,50,102,53,50,52,100,55,98,99>> =>
                       <<"±uUBDbYDH53AO4H4bW03jy02eEQslh5iPfNY/Er1/LXg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,53,51,52,48,51,54,
                     48,45,57,55,57,52,45,52,99,55,55,45,56,102,56,102,45,51,
                     53,52,98,98,56,48,100,56,51,101,51>> =>
                       <<"±nnT0WLkZLQKCHUN+KoMu4RyACKkd3AnOLJ54CF5ew2Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,56,57,56,50,101,48,45,
                     51,101,53,52,45,52,57,101,55,45,97,98,55,51,45,54,49,52,
                     56,102,51,100,57,102,100,50,102>> =>
                       <<"±y8YPo9DR+E0miWWVAMr4hDb8cNWIIGyeNVTyOWsk5ug=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,48,100,53,102,52,102,
                     45,97,50,99,54,45,52,53,99,48,45,98,99,48,101,45,97,102,
                     57,97,49,100,51,49,49,55,48,54>> =>
                       <<"±B7Xu2sq59W/GUJcNerrGiagp1799HaEYp22AnaViyf4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,100,55,53,100,49,100,
                     101,45,100,99,99,97,45,52,54,55,48,45,97,99,102,54,45,
                     51,99,52,98,51,54,49,99,49,51,50,51>> => 
                       <<"±nW4356LZf1HNHez0V47mvkwV2dvtKfxUXLjdp03L9No=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,100,48,100,48,97,56,50,
                     45,51,98,56,101,45,52,102,52,56,45,57,101,49,49,45,48,
                     49,52,99,99,49,50,49,54,50,50,48>> =>
                       <<"±L7flbxiivD5Sayj3eU7ErgGpldp0RP7eyAH0jBsGxFQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,55,48,51,52,53,54,
                     53,45,56,53,51,99,45,52,100,48,99,45,98,50,50,54,45,53,
                     102,54,53,48,48,99,97,57,98,54,48>> =>
                       <<"±AmFHvMS58KSJb0BKJt1fyLVUb4i/IKe7a6LWSwX6o0M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,56,54,52,55,51,101,54,45,
                     52,100,57,51,45,52,55,53,53,45,97,100,98,101,45,55,98,
                     52,49,100,48,56,52,51,99,99,51>> =>
                       <<"±6H9zOO8GTOqcr73EXUi//98+ZFPZHPW1dg9idV8aNBo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,52,101,53,57,57,50,45,
                     48,49,50,48,45,52,100,98,97,45,98,48,97,51,45,98,52,49,
                     97,97,54,99,97,102,54,57,48>> =>
                       <<"±XsLpBi7glZ87P0kWNCDDrScQEta9CjPBnmjuKN4QF2w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,53,99,50,101,52,55,
                     99,45,49,100,102,99,45,52,51,99,98,45,97,48,49,53,45,49,
                     97,57,101,53,51,53,56,54,102,53,49>> =>
                       <<"±tcNYNE/hP/qZfkb/TT/kpHi7FFfxOvqJZXwUn9n2rjw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,98,102,51,54,53,
                     102,57,45,102,55,54,57,45,52,50,49,50,45,56,55,51,101,
                     45,98,54,54,100,102,51,57,98,98,102,55,56>> =>
                       <<"±8twQGF0xLSefy0+qxbi03POosnF/dzFcP8ApUmJKcm0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,57,100,98,55,53,53,45,
                     48,98,57,53,45,52,101,98,50,45,97,51,49,98,45,50,101,50,
                     53,53,56,101,57,51,57,101,102>> =>
                       <<"±Y9qwPlJJt/FqBk28Iimo6pAdJoK63bdoRsFR/upX8ZE=">>,
                   <<0,0>> => <<47,1,2,59,0,2,111,130,5,108>>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,101,53,57,51,55,48,45,
                     53,98,50,49,45,52,99,50,52,45,98,55,101,97,45,53,49,56,
                     56,50,57,56,52,101,56,55,48>> =>
                       <<"±LNq2szxy4Dnc/Vipd/Z97CZDQIgzuZ1LKKkqGH95tCg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,48,97,49,56,56,101,52,45,
                     57,53,102,56,45,52,101,48,57,45,98,101,99,54,45,102,49,
                     51,98,54,51,48,57,55,98,102,101>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,99,48,53,51,53,51,45,
                     101,53,53,97,45,52,53,52,54,45,97,50,100,55,45,55,51,99,
                     56,101,55,53,99,52,98,52,52>> =>
                       <<"±JPlxG3J68/lDhAUvGf78ujaDq+IYMUz1x1D703sRc24=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,102,100,102,102,101,
                     101,45,52,55,98,99,45,52,99,99,98,45,57,97,53,50,45,55,
                     56,51,100,49,98,50,50,99,48,49,54>> =>
                       <<"±JyOTzWHhoBzVSgQHyJrzWUitWZtwPZTGSFHYg0HVVbQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,98,97,49,55,55,55,45,
                     49,48,53,102,45,52,57,48,99,45,56,49,48,50,45,100,51,99,
                     56,52,51,55,48,98,101,98,49>> =>
                       <<"±V1tGE3/hH+qfRAXextaJJokz8/qJgY2SEn5AtQpH3jA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,54,51,56,99,48,54,97,45,
                     51,55,48,98,45,52,101,48,97,45,57,50,49,100,45,97,50,54,
                     53,51,99,55,53,51,53,98,54>> =>
                       <<"±ljYKcZR3YE8JGTwP9Gm9pcHx83g49waduOSMgc6aG1E=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,53,101,49,50,55,
                     102,48,45,101,57,101,52,45,52,97,50,97,45,56,48,52,49,
                     45,56,97,51,56,97,99,54,102,54,97,50,57>> =>
                       <<"±QtJWY1bnAxqW9rMjcqq0pk/xY4j3cV7Pn5Z8/CUHYNg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,53,102,56,55,56,52,54,
                     45,51,100,50,101,45,52,57,54,97,45,57,97,56,100,45,101,
                     57,51,99,57,102,57,102,55,97,52,54>> =>
                       <<"±aTRrfKwDWdieB54ktGe45mrivxSvKCOLjCPh3M95FlA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,49,97,101,56,98,50,
                     45,54,53,100,97,45,52,52,99,56,45,98,50,99,50,45,98,48,
                     97,54,53,97,101,98,56,57,54,48>> =>
                       <<"±WArrukD2sdiFWnrbRmYjYIh07kYWPdqipPJtCknQwQI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,102,97,48,48,98,
                     99,49,45,54,54,102,50,45,52,49,100,57,45,98,98,101,51,
                     45,98,100,102,97,56,102,48,98,48,48,100,55>> =>
                       <<"±CrsU+e43HiU0AZ4zloKqWV309x2dmjy2cnjChX6lM4U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,98,51,97,50,55,98,51,45,
                     50,97,57,48,45,52,102,57,50,45,57,52,101,49,45,52,102,
                     56,99,54,98,48,48,52,54,54,55>> =>
                       <<"±3tLITKLN1MYsveqBli86lplMfKQSX+kgfZpVvspg/vo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,100,100,54,57,48,101,99,
                     45,50,100,50,99,45,52,99,97,98,45,97,55,52,57,45,99,97,
                     102,50,49,98,49,97,50,100,102,100>> =>
                       <<"±p4ZF2T/OzEOsIVcFpUfYwJGsIIhseWr9Ed1+/vVL8zU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,101,99,57,99,102,48,
                     45,56,57,51,52,45,52,102,56,53,45,98,102,53,49,45,53,48,
                     48,56,100,53,50,57,54,50,48,48>> =>
                       <<"±STmZ8BPfeej3g71kvItk+QMULQAa75cF5WA5Bq4ONzo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,54,49,51,97,57,99,45,
                     100,52,102,50,45,52,97,49,55,45,56,56,54,100,45,52,48,
                     49,57,52,50,57,100,57,99,53,98>> =>
                       <<"±E9WiFBbMavzuefnx+XyDTAm6xBSSTv1lJswEbdzvsqE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,57,55,102,97,49,
                     48,102,45,49,101,56,102,45,52,54,98,53,45,56,100,49,100,
                     45,97,101,48,54,52,53,53,102,99,56,54,52>> =>
                       <<"±/7TogDPuLgHIva4XZafkatU0nkQ59fgQMXt5MQ+qKzc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,48,50,55,51,97,102,45,
                     100,98,51,52,45,52,97,54,51,45,57,54,51,97,45,51,98,50,
                     51,101,97,48,97,54,54,99,99>> =>
                       <<"±SZYXQVVv15FqD+V5LO6ZQEyQS15TzsoE7iAnmpo85HE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,50,49,99,56,102,49,
                     45,50,57,48,54,45,52,99,52,55,45,98,97,48,52,45,52,102,
                     52,98,102,48,98,99,51,98,101,55>> =>
                       <<"±7J7wldHnBMdophbr30/ynrHrIOX2DKm/lMIV+XvfFtQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,57,101,50,102,56,51,
                     45,101,51,52,49,45,52,100,100,101,45,57,48,97,57,45,98,
                     102,97,50,97,53,51,102,99,100,51,49>> =>
                       <<"±OYmnoQ/B/Z3o+2avJg2V3zmEm/tN9cEiYA9jg5Pl1R4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,49,102,53,54,51,101,
                     45,100,101,100,98,45,52,98,102,56,45,98,101,51,53,45,53,
                     102,101,51,50,49,101,54,99,50,56,100>> =>
                       <<"±Ve63PP8jwsNSIVe6UOmX++wShCAFAyOB4Y4fW44QfJI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,53,53,52,50,49,99,51,45,
                     50,52,100,100,45,52,97,54,53,45,57,53,101,101,45,56,54,
                     51,50,98,52,102,100,99,52,100,102>> =>
                       <<"±aNoC94XHc0VeI33PPgW5hgtCqM45FiDgCr5uNt93hzQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,48,54,53,51,56,53,
                     56,45,57,48,50,99,45,52,100,49,55,45,57,100,51,99,45,
                     101,98,54,56,101,50,101,55,49,50,97,48>> =>
                       <<"±iacRZnC4L+/rSIB7rB7+Qw/4lePcizSSxt3MrMgc01w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,56,50,55,97,49,100,97,
                     45,101,50,97,99,45,52,56,99,97,45,56,97,98,53,45,49,56,
                     99,53,57,52,50,102,48,55,101,98>> =>
                       <<"±kX0z4eH4Zv+aIoWU/y4TOgW5p9iFAFkPaHGFjqy7wB4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,102,54,52,99,100,100,
                     45,100,100,99,54,45,52,54,52,52,45,97,51,55,48,45,52,57,
                     54,53,101,102,98,56,97,48,101,97>> =>
                       <<"±HtUBF50l8L4PlR+aBy0rEuntwTZnmaV11GMkgX4GiBw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,56,52,49,50,100,54,55,45,
                     49,51,55,57,45,52,100,102,51,45,56,102,101,52,45,99,57,
                     52,48,102,101,98,50,102,53,53,57>> =>
                       <<"±SmW9fSRrm4MEEjBdI1/EWf1MJj9Ck6/9hN3P71o6JQk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,54,102,57,48,99,49,
                     99,45,49,99,102,48,45,52,50,52,51,45,57,51,57,100,45,49,
                     48,100,49,48,100,56,97,99,98,100,55>> =>
                       <<"±znCjqPkoiNaK7p1ijpWmF+uhYxQvT0joKwBe1Y3hZlU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,99,100,56,98,48,54,102,
                     45,53,49,55,55,45,52,50,50,55,45,97,97,52,101,45,50,52,
                     55,97,102,49,53,48,97,55,52,102>> =>
                       <<"±GNz/n/ekiyrKmwI8rYY8D+/S1TkjpmE05DrNGlG1dIs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,49,48,100,100,51,55,98,
                     45,50,50,56,101,45,52,50,99,99,45,98,49,97,98,45,98,55,
                     49,100,54,51,101,48,98,100,100,101>> =>
                       <<"±997v71zrBXre4U9ChKbo8e7V0ZpVHbdvD+nuTwVI98Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,98,49,99,97,48,49,45,
                     56,54,55,100,45,52,53,98,100,45,57,97,49,99,45,102,56,
                     102,48,97,100,56,49,48,100,57,56>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,55,49,51,97,52,49,
                     97,45,53,49,99,101,45,52,97,48,57,45,56,57,100,48,45,56,
                     54,100,101,56,102,101,57,49,52,55,102>> =>
                       <<"±k4Izfg3ZD+dmeO8m0gvjRYAguLxdxjiuB6sKNeLCyn8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,52,48,56,54,99,53,45,
                     48,48,54,54,45,52,97,53,98,45,98,99,49,52,45,48,101,56,
                     53,49,50,102,97,100,50,57,55>> =>
                       <<"±ZFJ5OQtCJKI/CPEP12OzdBZ12v4IPIjuFYizYOA7Xdw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,99,57,99,49,100,51,
                     97,45,101,50,52,56,45,52,50,55,50,45,56,99,55,48,45,98,
                     53,54,49,53,99,97,56,54,100,99,49>> =>
                       <<"±v3QjaupiwRKwE5+EBx3KyZ8oHAuDctlQAfxrU98GmeY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,101,49,53,52,55,
                     97,57,45,53,57,49,52,45,52,51,55,50,45,56,49,48,100,45,
                     98,48,99,54,53,53,56,54,54,101,97,49>> =>
                       <<"±apt+7hGHvGLQjf+E/fpJqqQ2rIAJIJlSHCcNLA0Yq18=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,98,50,53,97,52,101,45,
                     57,98,48,54,45,52,56,49,56,45,97,55,97,55,45,51,53,55,
                     53,102,98,48,49,53,49,56,102>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,99,53,99,98,57,100,45,
                     56,100,53,50,45,52,57,53,57,45,97,56,53,52,45,49,50,55,
                     99,102,54,57,48,49,54,48,55>> =>
                       <<"±wbSI7zJ8y8puu3/+lS2/rO+5kATn/E1q2qC438MdbBc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,102,53,57,54,48,49,50,45,
                     97,98,53,54,45,52,49,97,48,45,57,101,49,54,45,54,48,51,
                     56,99,101,100,56,51,102,98,56>> =>
                       <<"±Dl/HMgos5rq9FwfERr1l8Ph8Pzwg7PgR/vXB476glbg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,55,50,55,51,52,102,45, 
                     49,54,55,102,45,52,50,53,100,45,56,49,48,98,45,48,50,50,
                     102,56,55,98,97,56,98,54,98>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,53,51,97,56,101,
                     99,100,45,54,97,98,53,45,52,53,51,50,45,57,102,53,50,45,
                     57,99,50,56,98,102,98,102,49,52,102,99>> =>
                       <<"±kXL8XXXRzpwtXGvxrFQ6taRajkJdd8dAxIQs4oG9Jcs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,56,97,98,54,51,56,49,45,
                     101,98,98,99,45,52,56,98,53,45,57,98,50,50,45,52,51,53,
                     97,50,52,54,98,55,52,57,97>> =>
                       <<"±4579s4kLEjIhx1xTZ8CjdQb//uar8KTQZ/dhhWkev/Y=">>,
                   <<1,0,0,0,0,17,107,101,121,49>> =>
                       <<25,118,97,108,117,101,49>>,
                   <<1,0,0,0,0,161,98,109,116,95,51,97,50,56,101,97,101,100,
                     45,51,102,51,55,45,52,52,56,52,45,57,53,97,56,45,56,57,
                     55,48,99,102,55,101,52,102,54,102>> =>
                       <<"±sE//i/CdvfvFj+Qerfkpvq3T/W9aaQ8UJkGawpawopc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,101,49,100,99,55,99,51,
                     45,52,56,48,101,45,52,51,49,101,45,56,99,102,101,45,97,
                     55,100,99,49,54,100,97,102,51,99,55>> =>
                       <<"±QGj/XpS09Q5tVhXTxPTih/hgHuWmcgHNKpckWIID65c=">>,
                   <<1,0,0,0,0,13,97,108,97>> => <<17,98,97,108,115>>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,48,48,101,101,101,101,
                     45,99,53,57,97,45,52,56,50,54,45,56,53,50,51,45,101,51,
                     48,51,57,100,99,53,100,100,99,54>> =>
                       <<"±V3FGFrvZMHpvFRUVsYJY0XTw14Qcx13iC94L57qH8b8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,53,50,97,49,52,49,45,
                     53,100,53,51,45,52,98,100,55,45,97,53,100,97,45,99,51,
                     54,102,48,49,51,101,51,50,50,52>> =>
                       <<"±jRySzKAGrXOHsAmA47bX+6u9Wobx6ySwme+0umi1uIU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,98,97,54,102,50,98,45,
                     48,50,102,98,45,52,98,49,49,45,57,101,48,52,45,100,55,
                     97,57,101,56,51,49,102,57,54,100>> =>
                       <<"±Mw/jJToKzufqM3iRil0/O+cSU7wI0dp9Dee5jESNkv0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,48,102,100,102,57,
                     98,102,45,99,49,49,48,45,52,50,97,49,45,56,57,49,99,45,
                     49,101,50,102,48,49,101,100,48,99,55,97>> =>
                       <<"±eLikY9jMkMnhLAnUmLEYGGn+EhO6GjC99d/cx97xL9o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,48,97,100,54,97,97,45,
                     57,98,57,102,45,52,99,98,98,45,57,100,56,97,45,56,48,50,
                     102,54,53,98,56,98,50,50,54>> =>
                       <<"±sU3hrvuLUNOHXyEXAndAPN4Su6SBxVfSli66V7EmmTw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,102,51,54,51,55,98,45,
                     98,56,55,55,45,52,100,51,52,45,98,53,48,100,45,98,99,56,
                     53,57,48,50,48,56,100,51,52>> =>
                       <<"±RvVN/l7IoPgll9pj0Tmze7kAamt9nDR+02sxRAQMaUc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,101,56,50,55,102,50,
                     45,98,54,102,49,45,52,57,51,55,45,97,55,49,100,45,99,48,
                     100,57,54,57,48,51,57,55,50,54>> =>
                       <<"±2jnXOoSIhChOQQCmmo194avUcIK7Hrdy3bSTRWHfA1o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,56,49,50,101,48,101,
                     45,98,54,49,52,45,52,57,100,57,45,97,51,101,51,45,97,50,
                     53,101,51,53,53,48,54,49,49,99>> =>
                       <<"±CxuETb81dQupxRBjiY0dH5eh9phwbql42wTurTS4pW8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,49,51,98,53,56,51,45,
                     98,55,50,101,45,52,48,49,102,45,98,99,48,98,45,52,55,49,
                     53,98,52,102,48,98,53,56,53>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,50,101,54,56,98,52,45,
                     56,56,48,49,45,52,54,100,55,45,56,99,97,50,45,48,49,102,
                     101,51,55,49,54,102,102,51,102>> =>
                       <<"±DxUp9PLPALBI4VoRvnMm0NxV8zwZAxeITsWbX2ZXafI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,54,50,57,51,56,49,98,45,
                     49,57,56,100,45,52,54,55,56,45,97,98,52,53,45,53,57,98,
                     50,100,53,99,51,50,51,51,53>> => 
                       <<"±QAZhethb1OW0ZC7onRsFg2cs41u0Fb7zzy+NjKY9OFg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,102,100,50,50,52,101,
                     45,98,98,48,51,45,52,56,53,57,45,57,49,100,56,45,100,48,
                     102,48,50,51,55,53,56,50,49,100>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,98,57,52,48,102,53,101,
                     45,54,99,55,53,45,52,102,99,55,45,57,102,54,100,45,99,
                     55,50,101,50,57,51,48,53,57,56,99>> =>
                       <<"±v/hZ03VZ7UYnCtdIcPCCMq9JE7cUvbLtOQuxMOKsCDw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,97,100,49,102,101,57,53,
                     45,101,57,52,49,45,52,51,54,56,45,97,48,50,48,45,102,99,
                     49,51,97,100,48,52,55,50,51,57>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,98,52,48,98,53,54,
                     101,45,99,57,55,56,45,52,54,54,101,45,97,51,99,53,45,99,
                     99,97,56,98,98,100,50,54,53,99,102>> =>
                       <<"±5N41bqXh2r30BDvWlLEBf2wrAOC1yyTssmSI+YLTUoA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,50,101,101,97,52,57,
                     45,51,102,100,50,45,52,102,54,49,45,98,101,53,102,45,53,
                     97,56,51,54,48,50,100,97,49,99,48>> =>
                       <<"±mkUqXgIbxXsyYg8BuhhgBIsV/GKdutriZ8RyJdIHVp4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,49,57,54,101,51,49,
                     45,100,52,53,54,45,52,99,101,48,45,56,102,55,101,45,56,
                     50,101,48,99,102,49,99,100,98,101,53>> =>
                       <<"±MAuHDYmiQX13XRl+Hfw2tuCSAqXF8DjqQQazqmA04Yg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,97,55,50,102,52,52,
                     45,49,102,48,50,45,52,54,97,99,45,56,54,99,53,45,102,97,
                     101,55,57,97,100,52,97,50,54,57>> =>
                       <<"±w+9Pv6PsWsd26JK6FozffKrmvb+iHGUqupmWp+wBWiw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,101,97,53,99,51,57,
                     45,48,99,54,98,45,52,57,55,98,45,97,52,98,98,45,97,57,
                     97,53,54,52,49,97,48,49,57,98>> =>
                       <<"±66Ner8E68y6FSQwKilbCjVAP/kM1rmMBJGrLpdIP/Vw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,57,99,53,50,48,99,50,45,
                     52,51,48,48,45,52,51,99,48,45,57,100,99,51,45,97,99,98,
                     53,100,50,101,53,54,97,101,100>> =>
                       <<"±CfZcf/B4VGXAkqKZdEf88giMO/1dc4pl+f23Ps0lP3o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,99,53,99,51,53,52,45,
                     51,50,99,97,45,52,52,56,49,45,98,53,98,55,45,98,97,48,
                     99,48,48,50,54,51,55,54,97>> =>
                       <<"±Sbw9fxDZtK1PUbeZolHtC8AEx/g5XBTFsHAYRnOrB8U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,49,53,51,56,48,97,98,45,
                     101,51,56,99,45,52,52,99,48,45,98,57,98,99,45,53,54,49,
                     54,49,53,49,102,57,48,100,53>> =>
                       <<"±x5J78vJ5ImPm2hxIzROAWi2Na2VmKLULZ0E3bllmohg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,50,57,53,101,48,56,45,
                     99,48,57,53,45,52,49,48,51,45,57,50,53,57,45,52,102,49,
                     48,57,50,53,101,101,51,48,50>> =>
                       <<"±d0vQqfXj5nvcm8z6HFxix/9cQEIE0wqwnoxNWxFfWhg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,56,102,57,97,101,101,102,
                     45,49,102,98,48,45,52,101,53,55,45,98,102,56,102,45,55,
                     51,99,56,48,56,51,99,55,101,53,99>> =>
                       <<"±z2IRjenbRT+FIWsJvqCys2hI2E55V6oGaNZlmJDbiA0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,48,100,98,57,99,54,101,
                     45,101,57,100,101,45,52,100,100,50,45,57,100,49,50,45,
                     99,54,49,54,98,56,101,98,50,53,52,50>> =>
                       <<"±ZCFzbHS6FlMydY6QXS0jLztEpdLSLvmrTmt3t26v1bg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,57,56,56,48,48,53,97,45,
                     102,52,100,53,45,52,100,56,49,45,57,97,54,53,45,102,53,
                     102,101,102,48,52,98,98,54,101,101>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,50,57,101,54,51,54,49,45,
                     56,54,97,48,45,52,49,98,55,45,56,51,57,102,45,52,53,49,
                     98,55,57,101,49,102,97,49,99>> =>
                       <<"±E2c9CqKc5gHDmXa4nVIyjv5JWaoxEeu7NDteag0ciQ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,102,50,101,57,55,51,50,
                     45,54,48,49,55,45,52,99,54,52,45,57,56,53,57,45,100,54,
                     50,52,49,49,54,102,99,54,57,53>> =>
                       <<"±nxsaLWgl4MN1NG7qhNaYsKS5S9Ib92n6XSQmm10f8wE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,52,48,57,49,100,49,45,
                     52,55,55,52,45,52,98,48,102,45,56,53,50,51,45,102,98,54,
                     48,51,99,56,102,49,54,57,102>> =>
                       <<"±KFMd3SZ0GFnWWO8b9+jqys06mVs3u+Nf7Q4E2wUUE6I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,99,51,48,99,100,100,
                     45,56,56,53,48,45,52,99,53,97,45,56,99,101,99,45,97,54,
                     54,56,53,97,102,52,52,99,49,49>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,102,52,100,50,48,54,56,
                     45,100,102,56,101,45,52,100,102,97,45,56,102,51,48,45,
                     55,52,97,97,55,48,52,51,54,99,54,100>> =>
                       <<"±1D1ZLzCXeK/rYTrdBIyNrglFoHAWeSHWMVmZ+HjAeFU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,52,50,49,52,53,51,45,
                     52,53,99,99,45,52,48,102,51,45,98,48,53,102,45,57,100,
                     98,53,56,101,100,57,52,57,55,52>> =>
                       <<"±IOxbMfS7zu1jTjeQeEdWLjSZSZBHu4P6QxnmrFtsuRs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,50,97,99,98,52,97,50,45,
                     97,54,54,53,45,52,51,57,99,45,56,55,97,100,45,97,53,51,
                     99,57,52,53,48,54,99,53,48>> =>
                       <<"±qvrTuAXvoLfmoq15F51LpJ5wcXpbHeep4gafODeHxPg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,51,57,54,97,57,102,
                     45,99,53,98,48,45,52,101,52,49,45,97,102,57,101,45,56,
                     52,99,51,55,101,56,56,97,49,54,100>> =>
                       <<"±XB8EK9uSlrPJFWj+r67+z3fkDV2jqSdEbdJNeUjCpYY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,100,98,102,57,55,52,53,
                     45,97,56,56,50,45,52,50,53,53,45,98,48,97,100,45,51,57,
                     53,102,56,50,97,97,101,56,56,52>> =>
                       <<"±4FfxD7KIczWnMYkHupEWebzHlVihjFH59T8RPyBThOg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,102,98,99,98,101,54,
                     45,98,102,52,56,45,52,52,51,99,45,57,97,51,54,45,53,99,
                     57,101,98,50,52,101,48,55,98,56>> =>
                       <<"±khcDBnfmLnMz9n/RurqXS44CVlOprUMKy2eJaIG8U5A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,53,98,49,98,52,55,97,45,
                     102,54,49,49,45,52,51,53,101,45,97,53,49,97,45,98,56,51,
                     48,97,100,50,54,56,51,97,99>> =>
                       <<"±GjzOA5hcWwaZaLSGHY3+sd8OdygSRAv4U3rUIHy0jSU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,48,97,98,52,100,97,49,45,
                     52,102,50,55,45,52,97,53,97,45,97,100,48,99,45,99,102,
                     102,50,54,57,52,97,55,57,53,54>> =>
                       <<"±uBNcwcFeC1yFJJiHlvHbmInXQg7mUS1sFpVfCskRq1Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,51,50,52,55,102,53,56,
                     45,56,55,100,49,45,52,53,55,51,45,97,49,56,49,45,54,56,
                     50,99,98,99,97,98,97,101,49,53>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,98,54,56,55,51,
                     101,55,45,53,99,99,52,45,52,53,100,99,45,98,98,55,99,45,
                     57,54,100,97,97,54,99,100,53,98,49,53>> =>
                       <<"±dVC+dCTvqdzs7IqnhFg16RCIZLSyTqo6bGA5q+yyQRM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,100,51,97,51,57,102,
                     45,98,100,48,52,45,52,48,99,48,45,57,52,101,52,45,48,51,
                     53,57,53,99,97,50,50,53,49,48>> =>
                       <<"±yN2rFkIkPwkVMgDeaKsTysdS3BiFP31S1Lq+Q9XKdFo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,56,102,50,51,101,53,
                     45,102,51,101,52,45,52,100,52,56,45,57,48,57,102,45,102,
                     97,55,48,52,99,98,57,52,48,55,97>> =>
                       <<"±N5BYf0RqW1w0EK03njDo8E6OIh6rjqDbpmq8K+dRsWo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,51,100,53,101,49,55,49,
                     45,50,54,99,48,45,52,51,48,99,45,97,98,54,52,45,50,100,
                     100,55,99,101,57,102,54,56,54,53>> =>
                       <<"±aJYpOXutuDc3g32bVJkMD7roEdHWkZveB7XAOQt/pHY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,54,101,55,48,97,53,53,45,
                     55,100,99,56,45,52,56,54,49,45,97,101,51,100,45,102,102,
                     100,101,54,98,100,53,100,98,50,100>> =>
                       <<"±nVfa3epX76Ox7WHud+1yInyRV6Rg0DIWhkuMFgXykY4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,48,56,52,48,97,51,45,
                     51,53,99,57,45,52,102,101,102,45,56,57,53,99,45,101,53,
                     49,54,100,101,52,100,100,55,100,51>> =>
                       <<"±/LO97h3Lexm/v9h61p02XgEHmLRFbvPjZTCbja+7dpM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,55,101,102,48,48,99,
                     45,55,52,98,98,45,52,54,102,101,45,98,55,57,57,45,48,97,
                     99,101,50,53,98,49,99,102,101,101>> =>
                       <<"±VyzP2P4Xo5sVpik0YZ1lYKz3XcKXmG25RjKl2hxCaZ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,50,57,100,97,101,102,52,
                     45,51,48,100,49,45,52,102,100,55,45,57,51,55,50,45,98,
                     100,56,50,55,50,55,101,97,53,98,55>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,57,51,50,51,52,51,
                     98,45,51,97,101,97,45,52,51,51,49,45,98,55,55,55,45,101,
                     48,50,101,98,49,54,99,48,97,54,48>> =>
                       <<"±Lkj8JWutMlzFhu31lbE6R5Fy3+ddwGDkIoLcqo9riPA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,49,48,48,56,100,57,57,45,
                     99,55,51,57,45,52,101,99,52,45,97,57,99,48,45,102,100,
                     97,56,101,56,50,57,100,52,52,53>> =>
                       <<"±zh6UrSAOG4YQ3XQWVHFwHCAZaXGbyrzc2mhsVrko3JQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,97,53,52,53,48,101,50,
                     45,49,48,50,56,45,52,54,101,99,45,98,98,50,102,45,52,55,
                     50,102,53,56,57,56,52,52,54,53>> =>
                       <<"±qrZYzq4B5eNOhUpKD3BjV64LYv1Zk/tMdZFyES9M0L4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,50,101,100,97,48,98,54,
                     45,56,102,57,56,45,52,55,98,50,45,97,50,52,49,45,48,56,
                     57,53,57,57,101,101,53,53,99,53>> =>
                       <<"±RzQNxANG/+XzePz8t2//5gVqnqJ7Zg7K8ZtrxEoFu6I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,100,101,99,50,48,57,
                     45,98,100,49,99,45,52,98,57,50,45,57,53,53,51,45,48,49,
                     52,56,98,99,101,99,50,100,54,100>> =>
                       <<"±Fj6l0E5flxeOGqs0YV1X6ePW5k33HvZvCtFG74XOPbs=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,99,52,51,101,51,
                     57,55,45,49,51,97,56,45,52,49,101,100,45,98,50,101,51,
                     45,102,54,100,50,55,50,56,52,50,53,57,56>> =>
                       <<"±erX3BXG/rRi9yLGQLkVfH5yWrH4uQzQgGCBnOS6z9WU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,97,98,57,50,100,50,45,
                     101,100,57,102,45,52,102,56,100,45,97,102,53,56,45,51,
                     49,99,54,54,54,49,49,48,101,48,102>> =>
                       <<"±VH/tOwC5SxXWj3M3DILYm3PI0mLYASwjAdXLehwiop4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,52,101,57,49,102,49,100,
                     45,98,55,51,52,45,52,102,56,55,45,97,51,56,48,45,53,52,
                     99,56,101,52,101,99,48,55,56,100>> =>
                       <<"±oufBXx6z87uvcl+wkcaJytaQwCIN3QABoHQVcdvNRes=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,51,54,48,50,52,57,
                     51,45,53,50,97,98,45,52,49,49,102,45,57,48,49,50,45,52,
                     100,98,101,53,54,53,49,56,54,50,52>> =>
                       <<"±mSeKYsEyXiCQTxq9eW7t9C0xakAaFmpA5/AKENMFGPw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,49,56,53,50,53,49,45,
                     51,57,53,50,45,52,49,49,53,45,56,54,49,54,45,54,56,97,
                     99,52,99,102,49,53,51,48,97>> =>
                       <<"±X33BxpwqBq2GRO2uKQ1hCRFSLyvJOS/yCh9wq86xKb4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,48,98,99,57,54,53,45,
                     50,102,56,48,45,52,50,49,99,45,56,57,56,97,45,57,102,
                     102,53,57,48,102,98,101,48,102,97>> =>
                       <<"±HrGeHixZOCp/N5nNWs/79MMUrl0r8YoUk6j1l7n/X/w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,101,98,100,55,102,50,53,
                     45,99,101,97,53,45,52,99,97,100,45,57,97,100,100,45,48,
                     53,100,102,48,97,54,102,101,52,50,52>> =>
                       <<"±3bpUmrRESqXZvZYojiS5GwlSbnATuuPjGu8vhO4Knl8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,52,98,54,50,97,57,45,
                     49,100,55,100,45,52,51,99,54,45,98,57,51,48,45,57,102,
                     98,102,100,52,57,100,97,50,52,49>> =>
                       <<"±E/55SQZguusJh2pGfYwZQK9ppWMfU5inCvkrZaTedU0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,97,51,51,54,56,100,
                     45,48,52,50,101,45,52,52,102,54,45,57,52,100,55,45,56,
                     102,48,99,101,100,53,49,48,101,55,57>> =>
                       <<"±4h1Nt3jW9dLWooz92YfD6g9uunFoMykRFHMO6/ykojk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,100,51,102,100,50,97,56,
                     45,50,53,52,98,45,52,48,54,101,45,56,53,97,49,45,99,102,
                     55,100,56,54,100,100,52,52,49,98>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,57,52,51,48,57,57,
                     101,45,98,97,52,56,45,52,54,49,52,45,56,50,50,100,45,99,
                     53,102,48,49,99,100,55,101,56,100,48>> =>
                       <<"±2UG2YTBnu9PDTj5iebl7EO4X1CoS9NHF7S68d8igvRE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,52,98,100,53,98,55,
                     45,49,57,97,51,45,52,51,50,52,45,56,100,48,100,45,102,
                     55,97,55,57,50,48,56,55,99,100,97>> =>
                       <<"±Pjs3zeb5TzchpY67IsLNWEbvlVqBL8+TDyNL2Zla5cE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,99,55,52,54,51,53,45,
                     101,48,100,99,45,52,99,53,99,45,97,49,53,102,45,98,98,
                     56,52,100,98,98,100,101,97,101,102>> =>
                       <<"±7jXAU+UnS30e3sQf2JRZ6cP/h3vLUl8HnzzVR//kWAc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,52,100,57,49,101,49,
                     45,97,50,52,100,45,52,102,100,50,45,98,48,52,102,45,98,
                     54,50,55,51,57,51,101,52,49,50,97>> =>
                       <<"±Ul3+o1BeGErY3cbsZftuGgCsMc0UjH178pVF0AixUHc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,51,48,48,52,54,101,97,
                     45,56,51,50,98,45,52,48,101,50,45,56,100,100,54,45,50,
                     100,50,102,52,54,52,49,49,54,51,56>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,48,99,48,51,99,52,52,45,
                     50,98,50,55,45,52,53,54,48,45,97,48,50,51,45,99,52,50,
                     49,99,102,50,100,52,56,54,51>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,56,99,100,56,50,55,
                     51,45,51,57,56,50,45,52,98,100,99,45,57,101,55,101,45,
                     100,102,57,53,50,50,49,48,55,97,101,52>> =>
                       <<"±RsDFikmebG2IEd6rSIkmSzYz1wd0nmscXJd0NR6H6nQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,102,51,101,53,57,48,
                     45,50,51,98,52,45,52,48,51,99,45,98,54,48,55,45,53,48,
                     102,48,98,53,49,57,55,56,52,101>> =>
                       <<"±qlZwMoGpkkGVQleo85jJLCgmhpB/KavRR5n/SYNJxCI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,53,56,52,97,102,48,45,
                     49,100,52,98,45,52,100,98,48,45,57,97,100,49,45,55,49,
                     51,55,52,52,50,50,54,102,54,52>> =>
                       <<"±Nca4zQuKr0BR60yqM3nTXHeYiiYStfl7pkhez0nttXI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,101,97,48,98,52,52,100,
                     45,57,100,49,56,45,52,56,57,102,45,56,54,97,49,45,49,49,
                     97,52,100,48,53,51,53,97,51,102>> =>
                       <<"±DwDh895563XYnhW82H63cGCclT+UAn6c+uuHcfTxCnk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,56,52,98,97,50,53,57,45, 
                     52,48,56,50,45,52,98,48,56,45,98,51,102,97,45,97,101,98,
                     101,48,101,48,53,55,48,48,56>> =>
                       <<"±s3MQR0BJG145s//DPrk3mavB4EiMABdeGmVnvYyCI98=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,50,56,100,99,97,53,49,45,
                     51,55,49,101,45,52,56,56,100,45,97,98,48,99,45,102,54,
                     49,49,53,50,50,102,54,57,53,53>> =>
                       <<"±LOcU8fd+oKXp5qE+vfVENuas4unG0dulmZMJXgIahWA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,50,52,54,98,100,98,
                     45,48,54,57,102,45,52,54,102,97,45,57,101,56,57,45,57,
                     53,51,102,55,54,49,98,49,48,54,98>> =>
                       <<"±twhGY3DJkwAablXPImHd00a5sM3iirw3q+gmxONv/lQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,102,56,102,100,102,
                     101,53,45,99,50,50,97,45,52,48,100,100,45,98,52,55,48,
                     45,99,97,101,102,102,54,99,97,52,100,57,102>> =>
                       <<"±hmarKVWtW6nw7LQ8Bdrk5+qgqR01NoFLHVNmjWc/Iqc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,97,97,56,97,57,52,54,45,
                     97,50,48,102,45,52,98,55,56,45,97,57,56,101,45,51,99,51,
                     57,53,99,98,49,98,48,51,53>> =>
                       <<"±r+BvVyYPF1XSV8cZKIp7mELec38w4m0djdILlTlLaWw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,57,97,56,97,57,51,45,
                     54,57,55,54,45,52,97,97,99,45,56,54,53,98,45,57,57,101,
                     57,56,48,102,102,53,52,57,100>> =>
                       <<"±3SkK1Hmkuls4kXcDr09aeCPh31KSwmYkJJzAwrUZZcc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,54,99,48,48,51,101,45,
                     101,101,49,54,45,52,55,98,54,45,97,51,100,97,45,49,54,
                     102,53,48,48,54,55,98,100,97,48>> =>
                       <<"±EplwrIhdxFC1KAe+vM7RwAaDoX/+i5JJVTYUE7U3uiQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,50,57,99,50,101,53,102,
                     45,52,49,53,55,45,52,50,55,49,45,98,97,48,56,45,100,97,
                     54,51,53,53,102,48,49,57,97,56>> =>
                       <<"±YEFPURA7mgUY5xcIerbXKocqlDuMLmdzZ9ltxYquWHk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,48,50,98,55,48,97,45,
                     50,48,55,54,45,52,57,102,98,45,56,57,51,55,45,51,50,55,
                     100,57,54,49,100,102,57,99,51>> =>
                       <<"±pcg+uLP6KNTYWJMhcH1v48GZwq/V4Olpql9KpvyFlnc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,100,54,57,51,53,51,
                     45,99,102,57,54,45,52,102,49,98,45,98,97,102,48,45,99,
                     56,97,102,50,101,101,53,51,102,56,102>> =>
                       <<"±Hv+2nGLpd4FJyRMDBp6mICl8aXExwe7qYv0mndbzpH0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,52,56,51,97,53,55,
                     98,45,56,51,48,101,45,52,56,57,98,45,56,50,57,54,45,56,
                     51,53,100,52,54,99,100,52,100,53,52>> =>
                       <<"±6JsHC8yubnBt5Qt+nBkLbI1Wqf+BRhnZ1teFdixcVZQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,55,98,50,57,53,52,50,45,
                     55,99,56,51,45,52,53,56,97,45,56,56,101,48,45,56,97,57,
                     51,99,53,57,98,51,102,54,100>> =>
                       <<"±0VdezumxXCd/QpouOG9PAzxAw1a+tiwpUg8X8hrGMGM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,48,100,97,54,53,53,48,45,
                     100,48,53,48,45,52,102,99,48,45,57,53,48,56,45,49,55,56,
                     56,52,51,102,52,101,48,52,99>> =>
                       <<"±ebGkNMqO7b+fUq2pT6sWNNUaOjtEnO1csz27kh1U5As=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,51,54,98,98,99,52,45,
                     49,99,57,51,45,52,49,53,57,45,57,53,50,97,45,100,56,100,
                     102,48,99,98,52,52,49,50,97>> =>
                       <<"±3ycdjhbBIuwloAd4iHsmeP5EJJaYZ0OBliuRGPNSDug=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,102,49,97,54,55,53,45,
                     52,54,52,102,45,52,54,53,56,45,57,55,101,100,45,50,100,
                     50,99,99,50,99,53,99,50,53,55>> =>
                       <<"±zPtJCRNdksn6p/XYmdde70NqGo/Gj2rNQlQqXPyEkto=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,98,55,102,49,97,97,57,45,
                     54,53,101,52,45,52,98,48,56,45,98,99,48,52,45,101,97,54,
                     56,50,57,52,52,51,100,51,102>> =>
                       <<"±z0ae2Pg2FfV/RGnkxeU9FXZutF21NzS9O77FyCsgMxI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,56,100,57,99,54,100,54,
                     45,57,52,99,102,45,52,102,51,55,45,57,49,56,54,45,102,
                     49,56,55,55,55,101,56,52,102,55,101>> =>
                       <<"±Hv+2nGLpd4FJyRMDBp6mICl8aXExwe7qYv0mndbzpH0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,49,49,56,53,48,97,
                     45,48,57,55,100,45,52,101,51,101,45,57,57,54,52,45,102,
                     97,53,56,56,97,49,55,97,51,55,54>> =>
                       <<"±1nPQ+yHJx6IbfbMZni55FguPJSh5GPZ7TskjenxErpw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,99,51,49,49,100,52,50,45,
                     98,49,48,57,45,52,54,102,56,45,57,52,53,52,45,55,51,50,
                     97,101,49,57,54,57,51,97,99>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,55,100,101,57,100,55,48,
                     45,50,50,50,102,45,52,53,54,99,45,56,48,54,52,45,55,99,
                     56,54,101,51,102,52,101,55,102,53>> =>
                       <<"±wrtMEM3WJr2QNZuUmg/T34uQY2/QWlyJQUA+l1/c79s=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,55,101,48,49,49,98,
                     45,55,49,100,51,45,52,56,48,100,45,97,98,57,57,45,55,49,
                     102,97,56,56,51,100,55,54,98,98>> =>
                       <<"±yCvWBaa0GTejGkHK/FouZnFu3p+6bo7uHV7iveKN1+M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,99,102,57,101,53,51,
                     45,98,56,55,49,45,52,48,54,52,45,57,53,102,51,45,54,97,
                     97,97,48,52,55,102,52,53,99,56>> => 
                       <<"±8Za2LaK/fffwWPjPplC0YUnptip1ZTYUwZAR5dcXwLc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,56,54,102,49,101,97,51,
                     45,54,98,56,57,45,52,49,54,48,45,98,48,97,99,45,53,102,
                     51,99,51,52,102,54,101,51,56,98>> =>
                       <<"±pab2H88FPK8JiA1m8bm/SQWuNqUDCfwkcBQtInypSds=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,101,97,53,101,55,51,50,
                     45,48,101,98,98,45,52,100,49,97,45,97,48,49,102,45,53,
                     98,99,52,102,51,52,48,54,102,52,56>> =>
                       <<"±SWYcJMF80G/DEgCbElnJyR+PJSziSf4FZV4DYu+q0Bw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,51,99,53,49,100,53,
                     45,98,51,48,57,45,52,56,101,50,45,57,55,52,49,45,52,56,
                     100,55,57,50,49,53,49,55,48,57>> =>
                       <<"±Z2tXJsphH9MwM+9oqVyYgLbmPOB03wAK5/2mfVzKAQk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,99,52,56,100,52,51,45,
                     52,51,101,48,45,52,101,50,101,45,56,50,55,49,45,53,55,
                     55,101,101,54,56,98,56,54,48,102>> =>
                       <<"±zdWfetPZDCOaOFuAlIBC9TTmKDsTD9Jvs/DM8b3Ey6w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,49,53,57,52,98,101,100,
                     45,56,53,98,52,45,52,101,48,53,45,57,97,97,50,45,99,51,
                     100,51,99,99,56,55,51,49,57,50>> =>
                       <<"±6rhsGmNnLVZLpexD2wUPAIqqTV5Y54fnp4FnKTtisu4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,56,99,97,55,97,97,56,45,
                     55,49,55,102,45,52,52,101,99,45,57,55,50,54,45,55,53,54,
                     56,57,56,98,48,56,50,100,48>> =>
                       <<"±b16tdT6xX4FGLkXc2nxAmU5vMrqCvaQOtH8er+Ukm+M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,48,50,97,99,52,57,57,45,
                     57,56,56,51,45,52,100,51,51,45,57,100,52,57,45,101,54,
                     49,51,51,97,50,51,97,97,48,55>> =>
                       <<"±CjdV3yyANP8PB8MmG9wApnALNeAoRdqgn4EIjPnWzgM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,50,97,50,101,52,101,97,
                     45,50,53,49,101,45,52,50,98,56,45,57,97,55,97,45,54,53,
                     56,102,102,100,97,97,55,57,54,48>> =>
                       <<"±hu4srdhyff8g/fJLVj1Er5XlGouhV2aUfdwND2kWOhk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,53,51,49,100,101,98,
                     45,50,99,51,55,45,52,101,97,56,45,98,52,97,53,45,50,100,
                     53,55,51,50,55,54,52,102,51,99>> =>
                       <<"±7TVdkriXePkvMg3MzMUnXCjxZqvVJuwqNdXSfHwFdD0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,100,101,100,52,99,
                     48,55,45,100,53,50,56,45,52,97,54,57,45,98,56,48,55,45,
                     101,49,48,52,57,48,99,98,100,97,102,102>> =>
                       <<"±Yvgdat2MjXLHu9e7BqhooodiOj4zAQFhzx4p7JckVO8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,99,50,99,97,99,49,
                     48,45,52,54,55,51,45,52,48,52,49,45,57,49,48,54,45,101,
                     48,102,57,53,51,100,57,50,98,57,98>> =>
                       <<"±/VuCAFRCjLk1EYPS69pcXOneBoKxlE+7fzpcomYm+1w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,48,101,56,98,49,98,
                     57,45,53,101,97,53,45,52,49,101,102,45,97,49,51,101,45,
                     100,100,98,48,54,102,102,55,51,56,100,53>> =>
                       <<"±cOJXXjPXrtf7tOVqOPEH5u9Gt8skgFOuYDRSB6qNexg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,97,48,50,100,49,53,45,
                     102,48,55,102,45,52,51,99,50,45,57,97,52,48,45,101,53,
                     99,100,49,101,101,49,56,101,101,52>> =>
                       <<"±PYJKkgapE3FAJOphAcoqm/Pm7SoeeNlSB/Pk0Ct+otk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,57,102,51,102,98,48,
                     45,54,55,99,52,45,52,48,98,97,45,98,100,48,51,45,51,101,
                     57,48,49,101,97,54,99,100,53,48>> =>
                       <<"±qdzpJVxvm90gwSEWLGODvfatUlHp1miMLB4d2MEBQsA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,50,48,52,50,102,48,45,
                     48,56,99,101,45,52,55,56,100,45,57,55,56,53,45,50,54,56,
                     51,98,98,56,52,48,100,99,56>> =>
                       <<"±Fj6l0E5flxeOGqs0YV1X6ePW5k33HvZvCtFG74XOPbs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,57,57,53,48,57,97,45,
                     100,101,51,99,45,52,100,102,56,45,97,55,98,49,45,55,102,
                     57,53,57,54,52,54,101,98,100,99>> =>
                       <<"±jd8CiOYhe9wHRbUnv6H4yt46YNr6hBLOdcMbnfFbmMA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,97,99,100,99,49,98,48,45,
                     50,50,52,50,45,52,49,53,97,45,97,57,97,97,45,99,99,99,
                     56,55,50,102,48,100,102,51,57>> =>
                       <<"±Qa1fPred7mZ74IoZvoRn3pa4GgggJfc3ZFBxpAx8dvE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,100,54,50,49,99,100,55,
                     45,56,101,98,51,45,52,55,101,50,45,57,99,99,101,45,53,
                     49,53,52,57,57,52,102,54,53,51,55>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,50,97,99,50,51,100,45,
                     55,51,54,102,45,52,100,56,56,45,98,54,102,57,45,53,99,
                     54,54,56,98,48,55,97,100,52,101>> =>
                       <<"±mWyZcTqTVz2Kp77GbikhNSZqMz19eLYov64AOweu7yU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,57,98,50,52,52,52,
                     50,45,54,55,53,53,45,52,53,48,50,45,57,53,56,51,45,49,
                     57,53,56,52,54,100,55,102,51,51,56>> =>
                       <<"±Q5bV0pYbeewKt+HuQx4Xs85J3puppzNQY5zn8UK8Q7w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,98,48,56,53,101,97,
                     53,45,97,52,100,100,45,52,98,48,99,45,57,55,49,54,45,99,
                     100,101,97,102,100,54,51,54,50,99,101>> =>
                       <<"±Do48tc20kiNrpWdlJUXj/tHnGwTmgmVb9rIdcbT3xZo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,51,57,55,102,57,99,
                     45,53,48,57,52,45,52,53,55,50,45,57,56,98,100,45,48,52,
                     49,98,100,54,98,51,56,101,102,101>> =>
                       <<"±gQeaxF44GQxsuqPkj/7bqxpaBhdp6K48USe6U24bDQ4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,57,51,97,56,102,97,
                     98,45,53,98,99,102,45,52,54,98,53,45,97,54,97,57,45,102,
                     98,49,101,98,102,99,54,98,102,49,51>> =>
                       <<"±7lZ2K2/eDkXbhfBD6LM+rxNKmD3cWuihWjnQgsvxulE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,52,49,52,52,99,57,
                     45,52,56,101,55,45,52,98,101,57,45,57,98,50,50,45,97,52,
                     55,48,49,97,56,102,56,99,51,50>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,99,98,51,101,52,52,
                     45,57,97,49,97,45,52,53,101,53,45,57,55,56,55,45,101,48,
                     52,50,48,48,57,53,100,51,54,100>> =>
                       <<"±nrCmVJiLriRTwuvMAaU0X2sAlNVIZDGl9JUrQmWZj+c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,51,54,54,55,51,101,45,
                     54,100,54,57,45,52,49,53,102,45,57,57,52,48,45,51,99,48,
                     56,57,52,102,57,56,57,57,101>> =>
                       <<"±JYu7ZpiGSNHPp82XqP8359gaVazbh7IWmMevzpVrTOI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,54,98,101,102,55,51,99,
                     45,97,51,55,49,45,52,100,56,56,45,57,52,48,99,45,101,49,
                     97,52,49,101,51,57,53,52,99,56>> =>
                       <<"±kdE3G2waYxoOe+U83ar7BohFgJsWe1a1HyyESHRWZN0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,56,54,50,97,102,49,
                     45,48,51,48,102,45,52,51,50,102,45,56,54,97,97,45,97,
                     101,49,51,97,97,52,57,54,53,100,56>> =>
                       <<"±0nyEGveO6oHh6XPJkqtuAn8kc50Mjy5X3i7j3Zjip+I=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,49,97,99,100,55,54,
                     97,45,97,54,102,48,45,52,53,48,50,45,56,55,54,50,45,57,
                     50,49,99,101,52,52,48,57,97,100,51>> =>
                       <<"±AthyGLliiIQevBlMZIPot9JwK/W++Qo0Gjp5JZAZtxs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,51,48,56,53,102,49,101,
                     45,53,54,50,100,45,52,101,99,56,45,97,97,48,55,45,51,
                     101,57,54,55,101,100,56,98,49,98,55>> =>
                       <<"±urNuhYndbtKrA62HVHDgXGGsd3gx5BLL2+uHnZq2D4I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,56,102,52,100,99,48,
                     45,49,99,101,101,45,52,98,98,57,45,56,101,55,99,45,97,
                     52,55,101,50,102,101,98,51,102,55,57>> =>
                       <<"±eQNTDdhohSmRr32mWwXtdJf5Oo083oIvcsGSKS8wVYA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,48,49,48,56,98,102,45,
                     99,48,55,54,45,52,100,98,51,45,56,56,57,51,45,54,50,100,
                     100,98,50,57,48,52,100,48,99>> =>
                       <<"±TAdHL+psx8l06sJT5ZCStoYn9BIHHmFtJ70DRNLjEhM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,57,49,50,98,56,49,45,
                     52,48,52,101,45,52,50,52,48,45,97,57,49,55,45,56,101,53,
                     97,102,99,57,49,51,99,51,51>> =>
                       <<"±I2L7a6pTn4AxHwAmialByPvsuYD7vNQxPh1EshLB5bM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,49,49,48,51,99,97,99,45,
                     56,99,101,50,45,52,101,56,48,45,57,55,53,97,45,101,98,
                     49,48,48,102,100,101,102,100,49,102>> =>
                       <<"±zpKua/cvr8swC/SHtBJQ60AOG1VieVTYHzvKVW+iGP8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,57,98,102,56,53,53,
                     56,45,50,50,98,98,45,52,100,52,56,45,57,101,51,51,45,49,
                     54,99,54,53,55,48,98,97,53,52,102>> =>
                       <<"±M3XYTDJHRZBIZAIJSD7kcsmxlJONEvsCsoyEHZsjagM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,56,54,100,48,50,99,101,
                     45,97,99,56,48,45,52,97,50,57,45,56,51,53,100,45,53,98,
                     101,98,97,102,52,101,102,51,102,50>> =>
                       <<"±j1MqzW++98S+hmNa2lRuaBfvJJq8cT44oNW4aT06RIQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,50,99,50,102,48, 
                     100,101,45,49,51,49,100,45,52,51,102,101,45,56,97,55,53,
                     45,100,55,49,53,97,57,56,48,100,55,52,50>> =>
                       <<"±sCombRAZFw3TW6HUcHM8fHwBIqTTb+srcysaIq1Pyj4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,99,51,55,97,56,56,98,45,
                     100,49,56,53,45,52,98,102,54,45,57,51,98,101,45,100,97,
                     98,51,56,48,50,98,98,101,53,97>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,101,101,97,101,102,56,
                     45,51,100,56,56,45,52,97,56,56,45,56,57,54,51,45,56,49,
                     55,55,55,50,98,98,101,55,49,53>> =>
                       <<"±tfUgk7XK9lACTHXhOO+U5HkCcfNAlv+3O72XIG/d48w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,102,56,102,97,57,56,
                     45,51,98,52,101,45,52,51,102,48,45,98,53,101,56,45,53,
                     97,57,99,101,56,48,101,97,55,56,97>> =>
                       <<"±/DEm78jJxAq6UwbqbZIVHYl+kcduoOiX6jXccG9ysxs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,50,57,99,99,48,99,45,
                     52,52,101,98,45,52,102,102,57,45,97,49,52,56,45,53,56,
                     50,54,101,100,101,97,55,50,101,51>> =>
                       <<"±uTP0yn4aKIV2DUCgm5XYWhLXw/GtC2aWs7VemhGb17c=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,100,99,54,56,49,97,
                     57,45,97,99,52,97,45,52,100,100,57,45,98,98,53,53,45,53,
                     55,100,54,97,53,54,48,48,101,99,97>> =>
                       <<"±my8l4nDNt7A+B2OBu4DNqnf0wCrE9+jSSDE7BVrTGys=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,52,97,101,98,49,97,45,
                     48,55,100,56,45,52,57,52,98,45,56,56,50,57,45,56,48,101,
                     100,97,54,98,101,48,57,56,52>> =>
                       <<"±8Za2LaK/fffwWPjPplC0YUnptip1ZTYUwZAR5dcXwLc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,50,99,49,56,57,55,97,45,
                     99,98,52,55,45,52,48,57,48,45,57,48,50,57,45,48,98,56,
                     57,57,98,48,54,99,54,57,55>> =>
                       <<"±q/lHPPX1haVLAH/MkP4cbaWMKLWjJ0L57fPabk8Nsbc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,102,97,99,99,50,97,49,45,
                     100,51,52,57,45,52,54,100,102,45,97,56,52,98,45,52,54,
                     50,57,102,102,101,100,48,99,101,98>> =>
                       <<"±eAYjXaoNrBq+v7dsYb6+ANR8k1TNZgGzpIKb4v6pDN0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,57,98,57,54,57,55,55,45,
                     52,49,54,49,45,52,98,51,102,45,97,57,98,98,45,50,56,100,
                     49,98,48,49,53,51,53,100,53>> =>
                       <<"±li1O3Bz/uyJh2RIXe//FdTiNApa4YwA9DXES/UKghKQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,49,98,55,101,57,56,52,45,
                     53,52,100,49,45,52,56,51,98,45,97,101,102,49,45,48,54,
                     55,56,49,56,48,48,55,49,54,97>> =>
                       <<"±DijRHjuM8OBXG9FbgG2HJfctX1tI215iTRKR2ICP7Ak=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,101,53,55,102,99,102,
                     102,45,101,100,97,101,45,52,56,50,54,45,98,57,53,51,45,
                     101,57,100,56,50,99,100,99,50,52,101,48>> =>
                       <<"±BLDaKaydi2M2paFZdzdOxiPxF1A2HzHR2Z+7XPZYND0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,52,49,100,101,55,56,
                     45,48,57,101,52,45,52,56,102,101,45,97,98,51,49,45,50,
                     54,55,97,50,57,99,52,48,50,101,51>> =>
                       <<"±AWD/cXcNHNjDJYN1/Mzq8IoD5lLA64LIn21LVqUg+LA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,50,53,56,50,101,54,45,
                     99,97,48,50,45,52,50,101,52,45,97,51,50,100,45,48,49,52,
                     97,48,101,97,49,54,97,48,102>> =>
                       <<"±Z+yS/cWSZ8ww/613tfu7dBes7kqq99kSrUPZ9ngmgcE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,57,56,54,101,50,51,51,45,
                     99,48,57,55,45,52,97,100,48,45,56,102,100,97,45,48,99,
                     98,99,54,52,97,56,49,48,53,99>> =>
                       <<"±pTDronAFZcxf7e8pvjkQMeq6uQwPXaWDJAustz9Rvu8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,57,52,49,52,55,52,45,
                     57,100,48,53,45,52,51,53,54,45,57,101,56,55,45,50,98,50,
                     56,51,98,57,49,101,49,99,101>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,55,50,54,98,55,99,57,45,
                     97,101,97,97,45,52,51,100,56,45,98,97,102,48,45,54,54,
                     55,98,98,49,51,49,55,101,100,99>> =>
                       <<"±CSev7wSzy/MK9n5sNYMtIJAqvnH9eaKAKDWVOTMWlgc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,98,50,100,100,50,100,98,
                     45,52,98,49,53,45,52,52,102,102,45,57,97,102,98,45,51,
                     51,57,99,55,53,53,50,100,51,52,56>> =>
                       <<"±4R1kx84wMvLnV6GUZs8GGsP8V7DbJDsbYAyNCqRDmyw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,100,51,52,57,53,97,45,
                     57,98,100,50,45,52,57,57,98,45,57,98,100,54,45,100,54,
                     100,100,100,54,100,102,50,97,48,53>> =>
                       <<"±LK2XyOqjKiRKAN3zxAgR9M6srlpRPLSuR987le/AlHs=">>, 
                   <<0,2>> =>
                       <<159,0,160,143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,
                         189,142,114,202,123,16,128,162,215,23,130,121,128,190,
                         12,181,253>>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,54,98,52,51,48,56,45,
                     99,56,56,55,45,52,54,98,97,45,56,101,101,98,45,54,56,99,
                     49,98,99,101,56,53,102,55,100>> =>
                       <<"±rpTSm1EouHNCKBT8JyUUT6onHBlHDmZSt39YxHj6nzQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,97,50,54,52,101,48,
                     100,45,98,48,50,99,45,52,98,55,52,45,57,52,100,56,45,50,
                     98,57,100,57,50,51,52,97,97,48,99>> =>
                       <<"±sUchm8B2u2eGt7Rk5oS+7by9iICeeFEK10fLOoFIR4U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,50,97,102,48,51,101,50,
                     45,52,57,50,100,45,52,100,100,51,45,56,57,51,53,45,99,
                     100,52,49,56,48,55,102,97,97,48,57>> =>
                       <<"±Sxe554x6w7UxGHHIl05CYOFqmklsE6IyhynsBzkdgPY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,54,52,50,98,99,97,
                     53,45,49,56,55,52,45,52,102,53,97,45,56,97,99,97,45,52,
                     54,52,53,55,102,97,54,56,101,57,98>> =>
                       <<"±LB9mLXHQwmGWVqCdg6f5hWd9chFaDYlR5ojvh/J7auY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,102,51,53,100,50,49,
                     45,56,55,97,56,45,52,53,54,99,45,98,56,49,102,45,48,99,
                     97,55,99,99,48,56,48,101,98,102>> =>
                       <<"±Ccc1R59UvzgdNmdU5bVGJrc5alZA+TYF8c/jzomVbXU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,49,99,49,56,56,100,
                     45,101,102,50,48,45,52,56,101,99,45,98,56,57,98,45,57,
                     97,49,98,100,99,50,97,51,102,52,101>> =>
                       <<"±dOk28svAGiO6XsUBqQNkfP3BIX/bWqYQJHL7AARzMT4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,56,97,101,98,57,98,102,
                     45,51,97,53,53,45,52,100,97,57,45,97,97,102,101,45,100,
                     55,99,99,102,102,49,55,51,97,102,54>> =>
                       <<"±kcRKEhPchhhqy0TcaM2aJ1mXOq6Z8OO4eDhLi7YrbyI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,51,56,98,55,53,102,
                     45,101,54,98,57,45,52,101,97,102,45,57,49,56,50,45,49,
                     48,100,53,57,57,51,50,101,102,57,98>> =>
                       <<"±fp2Mq4K3yZqGT/7SBV629L7kXVc33y0qDlWxTOJNOoc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,54,55,56,97,57,48,45,
                     99,52,51,54,45,52,97,98,55,45,56,52,102,48,45,54,99,51,
                     101,52,101,53,49,99,100,53,57>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,100,50,51,100,57,54,97,
                     45,50,56,98,102,45,52,49,101,99,45,56,101,51,52,45,99,
                     100,98,100,98,52,56,100,53,51,55,57>> =>
                       <<"±pL4x3H5Do3fDnFhJHxZC0HCz02rDe9aY4EPbwE1KwzY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,102,98,51,99,50,100,
                     45,52,53,52,52,45,52,102,53,100,45,98,53,51,50,45,50,54,
                     56,54,52,54,52,56,102,53,50,49>> =>
                       <<"±B3rz95oQj45SuDry4pCUYOs0cPmYM4gIkxi7G4jl/VQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,98,102,98,101,54,
                     57,51,45,50,98,50,50,45,52,52,55,99,45,56,101,55,51,45,
                     52,50,52,55,55,98,54,56,102,50,56,57>> =>
                       <<"±wqZFCkk2KZl3cKGRrpmIq4GM4bdQHNqOAaSNXmqGNaU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,102,55,50,54,102,56,52,
                     45,55,48,51,101,45,52,98,48,57,45,56,51,49,101,45,50,
                     100,100,54,101,54,52,53,102,49,97,100>> =>
                       <<"±ORZaQAbaO4ZxuDXh5wHHoVsz5+barlIFCqEw7/8ijXo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,53,55,102,55,102,53,
                     45,100,48,55,49,45,52,102,53,100,45,56,98,51,49,45,102,
                     100,98,52,99,52,102,98,57,49,51,98>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,55,55,99,99,49,101,45,
                     102,57,97,51,45,52,50,98,57,45,97,49,54,49,45,48,100,55,
                     101,97,53,99,56,52,99,48,55>> =>
                       <<"±PkrkSS3aMtPyf7MfFCFdMUY9Gk6wLwAoNmihnhcHMvI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,55,54,54,53,54,53,45,
                     97,98,55,97,45,52,56,54,48,45,57,54,101,99,45,53,52,51,
                     50,101,50,98,99,102,52,48,57>> =>
                       <<"±ObPhylXn3he5VLszrR92546PGcbr4efQzhyFY6OGNCs=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,55,101,56,56,99,48,
                     98,45,56,53,52,52,45,52,102,53,53,45,97,49,54,49,45,101,
                     50,51,49,49,54,102,98,51,100,53,100>> =>
                       <<"±aE1syHRcT8DSzqafZkIzH/QVEX8/IzE6yOIErL7Z8qA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,99,97,49,55,54,49,56,45,
                     48,57,98,48,45,52,53,97,98,45,97,100,51,101,45,99,51,49,
                     101,99,102,53,51,97,100,99,56>> =>
                       <<"±cQxgZsuDvLBMo85jzLw2mfXHdYNnRprwSuEabeNBRXY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,97,98,48,98,100,49,98,45,
                     55,53,52,97,45,52,100,102,54,45,57,102,101,101,45,99,
                     100,52,55,102,100,49,102,97,53,54,51>> =>
                       <<"±Bhd4z7gmCWhA/zL6Iw1es+/qMgh5rdRGrx74cmcuxEQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,98,52,53,52,101,101,
                     45,102,52,52,49,45,52,49,99,50,45,57,51,57,102,45,57,52,
                     54,52,51,57,100,53,52,53,100,99>> =>
                       <<"±FO7f3Otu1QamtH0hRjNskpr2lls1T7H970g9a2Q+d14=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,56,56,55,54,98,57,45,
                     57,101,56,54,45,52,48,57,98,45,97,53,51,56,45,98,55,56,
                     51,52,52,102,57,51,97,102,52>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,100,99,53,102,98,57,98,
                     45,56,55,49,102,45,52,48,97,101,45,97,99,49,51,45,52,99,
                     54,102,97,54,99,52,49,102,98,54>> =>
                       <<"±F/sGXdH4s3miWT28NOOOrXw+IVuDofArze/t/pxJAjQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,50,51,102,97,56,97,49,45,
                     50,99,49,97,45,52,51,52,53,45,98,99,49,53,45,50,51,55,
                     55,99,97,52,98,50,100,99,54>> =>
                       <<"±LLmlwnjziHhpZ2BJ5VpA0rwncpFU2quEPddDuXfe9s8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,51,55,52,52,50,55,45,
                     54,57,55,51,45,52,98,56,102,45,98,99,53,54,45,101,102,
                     52,101,54,51,50,97,53,54,51,101>> =>
                       <<"±yjHucIgLRXoc2zBVUf1oZvyaeZceAt5rF6386rbD6AI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,97,54,52,50,55,55,45,
                     48,48,102,48,45,52,50,53,97,45,98,49,48,48,45,55,98,53,
                     53,97,52,51,55,51,102,101,53>> =>
                       <<"±e0qm72eWNflhnmL3QnZBsPATjYZpEyHt8pTMbZiH3FM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,55,97,97,51,49,56,56,45,
                     53,52,50,98,45,52,54,49,50,45,56,98,51,49,45,50,48,49,
                     101,99,57,100,101,53,53,100,98>> =>
                       <<"±l41h03K7kSR8IwSs01j2AYsYwl8ZcHiefaYR0fa0rSU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,49,54,101,54,57,56,
                     51,45,57,55,55,53,45,52,100,52,51,45,57,52,98,98,45,99,
                     48,99,100,98,51,102,102,50,100,54,57>> =>
                       <<"±GU8A3CfNCv6jq3awOJDH2XaAsst7kiG/oClGojLu1r4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,52,55,51,49,49,99,97,45,
                     99,99,101,56,45,52,54,48,101,45,97,52,57,55,45,57,51,48,
                     101,55,99,52,48,99,101,101,101>> =>
                       <<"±dWJpXAzh+FuAndnevvE5+WpS9sm8teIdwYWok8bEqDs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,52,97,102,55,99,51,45,
                     52,56,50,101,45,52,48,48,52,45,97,98,98,98,45,97,48,54,
                     99,98,97,53,56,50,50,48,51>> =>
                       <<"±6yhBjV59ssIn2pemwdnPlp48x8zX23DKCxNUAncRJVA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,98,56,54,100,97,56,
                     49,45,51,97,100,49,45,52,51,56,56,45,98,99,51,57,45,48,
                     55,97,56,101,52,57,100,50,102,56,48>> =>
                       <<"±tAaa08HdYTJoNIwhgaCmQ2CIrEh4vyoGPnO5bsOnHt8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,57,101,100,97,102,98,
                     45,48,51,97,98,45,52,50,97,98,45,98,99,56,56,45,49,48,
                     50,102,52,54,49,53,54,54,100,49>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,53,55,101,57,51,50,49,45,
                     100,100,49,51,45,52,50,99,56,45,98,54,57,102,45,97,101,
                     53,56,98,50,101,101,53,100,100,49>> =>
                       <<"±U1GOx2Z9G7q3wsA/H4+XiXr4JzBBiCRD8RMextAfZqs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,51,54,52,56,56,51,102,45,
                     48,54,49,101,45,52,102,57,99,45,98,101,54,57,45,50,52,
                     101,49,55,98,54,56,50,52,101,102>> =>
                       <<"±EjW/x7qphJlmKz/DijeptbzCEHktBNe9BMfv8BkDtRk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,55,49,56,49,53,48,45,
                     97,51,100,49,45,52,100,101,97,45,57,55,99,98,45,57,57,
                     54,54,51,100,52,102,53,52,49,54>> =>
                       <<"±BRjh6cx097xiyhisjUKs9HJ9EQ71nwIoAaGUfXMn2Rw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,48,101,101,99,99,51,50,
                     45,55,53,55,52,45,52,98,100,102,45,56,50,98,53,45,50,
                     101,50,52,49,54,48,99,100,54,102,56>> =>
                       <<"±HvqTWOKZbpfnj3dIqHPqEw61Km/OqWLeOfpl8n8I000=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,56,56,99,52,98,102,
                     45,99,101,101,50,45,52,52,101,50,45,57,51,98,99,45,97,
                     52,101,57,55,100,52,51,51,49,50,56>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,98,57,97,54,98,98,45,
                     97,57,50,55,45,52,97,49,50,45,98,53,101,55,45,98,99,48,
                     97,101,56,49,99,101,52,101,50>> =>
                       <<"±GKH9g6FKxZWmSfzur2HmZHHrdxbGLRjkSAqWowP6lf0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,101,54,53,49,50,
                     54,51,45,97,97,49,51,45,52,51,55,49,45,56,97,51,50,45,
                     57,99,55,54,51,57,102,97,102,52,48,57>> =>
                       <<"±XSFh1cqN94ncR/jFpNIxdoenLkV1Kluk6lPO6Jpsli4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,53,100,49,100,52,
                     102,101,45,51,102,50,98,45,52,52,52,98,45,98,101,52,57,
                     45,53,101,52,56,57,55,55,97,49,100,97,101>> =>
                       <<"±EFoiNoT8+sy4iN2XRjTG67ishzztE16jAgWrXTcEPFY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,50,54,55,56,102,99,45,
                     55,52,50,55,45,52,98,99,101,45,97,102,50,54,45,56,51,55,
                     53,99,52,54,54,97,52,57,98>> =>
                       <<"±Y3mPiHVBXNRG+diM9deIWXuNQd6e5OEUyUMQmptCY2U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,102,56,57,99,99,99,56,45,
                     51,99,57,51,45,52,53,56,49,45,56,101,57,50,45,53,97,51,
                     102,100,101,99,54,48,97,53,50>> =>
                       <<"±p5GDH3BxVgcjRd55efwhjo3BeXCurIU0mX9mq0fcjC4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,54,49,97,57,102,99,
                     98,45,57,49,56,50,45,52,48,56,49,45,97,98,56,49,45,52,
                     52,49,99,98,51,53,57,52,100,100,49>> =>
                       <<"±pYBcEo5CZ0SOF8dl2XUcj+doTx06N5s4Qa3EMrTWzeE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,56,53,51,52,52,57,45,
                     101,52,52,102,45,52,48,102,51,45,97,101,50,102,45,55,
                     100,50,52,98,101,52,48,54,98,48,57>> =>
                       <<"±VY7nEWGOs9KAdhf3xNuAI+nGuU0XtF8l0RbuCb1hmD8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,54,55,55,97,51,54,48,45,
                     51,100,100,55,45,52,57,49,100,45,57,48,53,56,45,51,98,
                     101,48,97,99,48,99,50,51,97,50>> =>
                       <<"±FJoTWetZPz+B9qso7PZE44849xZAa2Zs8xOSsSSxb8g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,51,52,49,50,102,52,48,
                     45,101,101,50,50,45,52,48,51,48,45,97,52,99,99,45,56,51,
                     99,56,50,57,48,101,99,99,52,50>> =>
                       <<"±Uy5iNWAh/A9zGeQr0ZesL8hyQ6ZbOg0/8HE/9FU4QSk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,54,51,102,100,99,
                     48,101,45,53,102,56,51,45,52,102,97,97,45,98,51,102,56,
                     45,101,48,50,100,54,50,98,49,53,57,52,99>> =>
                       <<"±Dsd4LOROaBBN8n21sf7CsWUlaWR9MKAm9LhYX4CrhVI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,99,98,49,99,56,52,45,
                     56,54,97,52,45,52,48,48,100,45,98,50,99,102,45,99,53,50,
                     99,55,55,97,97,101,97,101,102>> =>
                       <<"±Oiyc5mvfhbTeb4Fl02/KDW+USdL0vzWSf6VDmfbpp+o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,49,101,55,97,51,52,
                     45,53,97,100,97,45,52,51,101,51,45,56,56,56,49,45,101,
                     100,48,52,97,100,48,57,53,99,97,51>> =>
                       <<"±MdgPEEcLZClCXcX4Z5BDmcAzqerlb8hsmhYGGNHUNb4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,50,55,102,98,49,57,
                     45,100,50,102,50,45,52,98,97,51,45,56,98,51,50,45,98,
                     101,57,50,55,97,102,57,51,56,53,56>> =>
                       <<"±kJgcSujXRlgiKPk1uFD+MlA/u4S48GMDf7rspyoeBr4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,57,56,102,97,48,53,45,
                     97,56,100,98,45,52,53,56,50,45,57,50,48,49,45,51,50,57,
                     48,52,98,56,100,54,98,97,98>> =>
                       <<"±RVfIxEx/7ObjkSaOTM0onzP9DTBQ5h7uHfB1tqJP5DM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,98,98,48,52,54,97,45,
                     49,101,100,99,45,52,99,98,99,45,98,55,50,54,45,100,98,
                     50,52,53,54,51,102,57,98,51,50>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,97,99,57,100,51,100,
                     45,48,50,48,97,45,52,99,49,49,45,97,48,49,99,45,97,57,
                     50,97,57,49,97,101,99,101,55,53>> =>
                       <<"±D8y33WHoTD8HNb8sK756lQ/TH0KdSiR6bKqabrvnkm8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,100,52,55,97,98,57,99,
                     45,57,52,48,101,45,52,52,53,49,45,57,51,56,48,45,50,98,
                     49,48,53,50,99,49,99,50,55,99>> =>
                       <<"±cpcjTtL6GGoCefu4fj76Y+xOX1F3uyBxg/AIiQ+3C6w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,48,55,55,54,98,56,49,45,
                     55,98,55,100,45,52,48,100,48,45,97,101,97,98,45,97,99,
                     50,48,98,49,100,50,52,56,51,102>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,99,49,50,100,55,50,45,
                     53,99,52,100,45,52,100,100,57,45,97,53,99,49,45,56,53,
                     55,48,57,50,53,53,48,102,97,98>> =>
                       <<"±qhMWXza7Ks2e4DSHImHDWGpjAg8imcpWUJkqoJ275Hk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,57,50,48,49,52,57,45,
                     48,54,54,50,45,52,56,55,51,45,56,54,57,53,45,55,98,98,
                     102,100,102,100,99,100,101,51,98>> =>
                       <<"±N7WwYRfV0S0KY4bksA+hOkGuVC6wcDkQtlZEks0sPJM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,49,99,57,56,53,52,
                     99,45,55,56,55,100,45,52,49,98,48,45,56,53,53,97,45,102,
                     101,56,101,54,57,52,97,57,50,55,51>> =>
                       <<"±DgvRTBrYX8k1X2rPggeTBTdZEhG45RRPrGhZSVQtg2Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,102,50,100,56,57,48,
                     45,53,49,99,97,45,52,51,51,53,45,97,56,53,55,45,54,51,
                     101,53,52,101,51,99,49,52,97,51>> =>
                       <<"±ggkFJJjvm/60G5JWkc6+Sm2aJL9XF9AOwM/uIlq6pXs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,50,99,53,101,55,48,45,
                     49,101,101,97,45,52,100,52,97,45,98,101,51,49,45,54,55,
                     57,48,97,97,99,100,57,101,102,97>> =>
                       <<"±jDhPBFfBAAMw7Gy1iQUvxLVO/dbkKZvq/VPZB86VlNo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,48,55,101,98,100,
                     54,57,45,102,54,98,102,45,52,99,50,99,45,56,56,51,53,45,
                     56,53,54,54,57,97,50,97,49,98,48,102>> =>
                       <<"±Ir2XwdiSySpxxYueFR5EMO7F1zu1FN0GcPbyCeRokGY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,101,55,49,100,102,49,51,
                     45,55,50,57,101,45,52,57,101,53,45,98,56,51,55,45,48,55,
                     98,101,53,100,49,100,54,53,51,50>> =>
                       <<"±rDRgp+aaeWd8Z1IDyL3A+Zz/syUle46fu6ootOFukK0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,54,98,55,54,99,56,
                     100,45,100,52,101,53,45,52,98,56,97,45,98,55,55,49,45,
                     56,51,56,101,50,98,51,57,57,56,57,48>> =>
                       <<"±TqZTPCYMh0Sy9TEaRRFpLn5dx0sGh2QHE/+ggSf84bg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,56,57,101,51,57,55,98,45,
                     100,55,57,53,45,52,52,57,99,45,98,98,52,97,45,100,98,51,
                     99,99,97,51,98,53,97,53,57>> =>
                       <<"±TaDREOrr8raA3RX1qHMlwc/t3LIU1VHBDJjf6gVBlps=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,99,99,98,99,48,53,45,
                     55,98,50,51,45,52,53,50,52,45,98,51,101,97,45,54,51,48,
                     52,100,53,54,57,57,54,101,54>> =>
                       <<"±GUytMqscVzbK3z6pAe59v1YJBg5zyJ3rBR6NJKZ7vkM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,101,100,54,101,102,99,
                     45,55,57,50,102,45,52,101,50,57,45,57,101,55,50,45,49,
                     54,101,49,55,49,50,51,50,99,100,57>> =>
                       <<"±5LlV9/fgtwZcFD9VzpLWaTICRnNcwdxO5WVOfoasy7E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,100,99,57,54,55,99,45,
                     54,52,100,50,45,52,100,54,57,45,98,52,102,53,45,54,98,
                     99,52,100,55,54,57,56,50,48,98>> =>
                       <<"±62P8W6drulIYFfCjQoM4oImyIzHcs0iZLs7JjIfMujs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,50,48,99,49,50,101,
                     45,48,56,101,102,45,52,99,54,52,45,97,98,57,51,45,98,98,
                     49,55,52,50,56,54,100,51,102,52>> =>
                       <<"±F33UYheZn013UIL/xCfhcKRQbxJr2PE/PLECwDRmIZE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,98,102,50,56,98,57,
                     45,48,97,52,57,45,52,55,49,99,45,57,101,99,99,45,49,53,
                     98,57,54,53,49,98,51,99,54,56>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,50,57,56,99,49,57,49,45,
                     49,99,52,97,45,52,54,102,52,45,97,57,100,102,45,52,51,
                     54,49,97,51,102,48,48,100,53,98>> =>
                       <<"±9yVEOeF/PiX6owGdf0zDqryuz0yP8IN8+zBwdqpGfsA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,98,102,51,100,52,
                     51,101,45,56,49,49,56,45,52,101,53,98,45,98,57,98,48,45,
                     97,56,99,57,56,53,55,52,57,53,57,101>> =>
                       <<"±y43BtjV7U+7RfOrp+aCoSdDGZ0EWv9IqPuDK8gaPUTY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,48,97,99,50,101,100,57,
                     45,53,57,53,55,45,52,97,54,49,45,56,99,51,50,45,48,50,
                     57,53,57,53,51,49,51,54,102,101>> =>
                       <<"±ZJLdrpAiaCkMdxEJYGByahtmHWBNLG/uFMOIhbZUPRs=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,98,97,99,102,48,48,
                     56,45,49,48,50,98,45,52,97,102,51,45,98,53,102,98,45,52,
                     52,99,51,53,99,54,102,51,56,52,102>> =>
                       <<"±CVScfuZWXZ3xq3LD7187eaOdfEwqqT7zJhLM9XGMszU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,53,54,54,98,55,101,101,
                     45,51,56,54,97,45,52,48,99,101,45,56,50,53,50,45,101,53,
                     49,51,54,98,56,48,48,50,50,54>> =>
                       <<"±h2JMZjDH+uqo6Dy6gYip/oKdaMIv8h5H+jJFw448/M0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,55,48,49,48,100,101,54,
                     45,48,100,98,98,45,52,57,50,48,45,56,49,51,99,45,48,97,
                     102,99,101,52,55,56,50,57,99,49>> =>
                       <<"±bm+HLCgN1b6AwFC5oDuVT01MQMNZs3w92ZNu1oLZnLg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,49,98,52,48,56,51,48,45,
                     55,51,102,57,45,52,55,101,97,45,57,52,52,98,45,101,49,
                     51,99,57,98,102,102,53,55,99,54>> =>
                       <<"±g0RVrxtLBF6tBZIJBh8YnU6wcpWFNx1zoMp8932cXNQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,101,56,50,48,55,98,45,
                     97,50,53,100,45,52,56,99,53,45,97,50,56,102,45,57,52,49,
                     52,97,101,52,48,100,55,48,102>> =>
                       <<"±UteZMdlZSdRtfsQBdZjGJwFXI6BW3hUift2FvQv2W0o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,99,55,100,57,57,100,50,
                     45,97,98,51,55,45,52,52,97,54,45,56,100,49,52,45,48,51,
                     100,51,53,54,99,57,102,57,98,98>> =>
                       <<"±dwI8tMZ4yArVXttGFPl0QuJNGfy3oPp0cMO/l4Glguo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,53,98,52,53,51,49,
                     45,53,49,101,55,45,52,48,57,100,45,57,102,56,53,45,100,
                     51,55,100,57,53,97,101,100,52,48,99>> =>
                       <<"±WnDc0PQJn5FzLBLA5VYmZvN4i/YogwQyab8qvKlId3E=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,53,102,54,53,50,48,
                     50,45,51,48,99,49,45,52,52,98,97,45,56,55,56,55,45,50,
                     55,98,53,48,100,99,98,55,53,56,102>> =>
                       <<"±1tfs4NSWm3wDRiDjykLx6ICNVV1AEHatqc/ho1M+n6k=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,98,54,56,53,53,98,45,
                     48,48,100,99,45,52,51,102,100,45,97,51,50,97,45,52,53,
                     53,50,52,97,54,53,52,99,51,101>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,49,102,52,50,48,51,101,
                     45,52,102,52,97,45,52,51,56,48,45,97,49,51,99,45,52,48,
                     50,54,101,55,52,101,102,102,102,54>> =>
                       <<"±CmFZUA2vtzAp4TWRDt/bwSqHPkWTyimc5IOvGpU45EQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,48,54,56,50,100,98,
                     45,99,99,56,99,45,52,48,101,99,45,56,97,52,97,45,100,99,
                     101,53,55,51,102,57,55,100,98,53>> =>
                       <<"±z1ePNl2fcpOW2bSl2Qwqdexw4bMo010xxSFm//vTwS0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,101,52,99,49,57,97,
                     48,45,98,57,101,55,45,52,100,48,98,45,56,101,102,49,45,
                     54,52,97,102,100,50,56,98,51,51,54,99>> =>
                       <<"±hh9JoVwz5ItL9HrbjecdCV9dBm5gaz1Ho74FY4WAVuA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,49,97,55,97,55,50,50,45,
                     55,52,49,101,45,52,99,101,57,45,97,97,97,97,45,49,97,99,
                     49,100,99,56,51,97,49,57,56>> =>
                       <<"±XAn4iDssAkqtyQV1PsOiqQamHI6QF1Z4cW6VgAfyBT8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,49,99,100,54,56,
                     53,52,45,50,49,52,99,45,52,100,51,55,45,56,98,49,54,45,
                     49,102,97,56,50,97,49,49,97,56,102,53>> =>
                       <<"±LHSX+C4XMTOLQVgPUgjknpBSIZOis+6+Os1kAcHpoF4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,50,55,102,100,50,100,
                     45,97,101,50,101,45,52,100,52,55,45,98,101,49,100,45,52,
                     55,97,57,57,55,99,51,99,101,56,99>> =>
                       <<"±m43QIwjUqq0yW7XL1Ml3y74roONq8enD6iWQDA0jWok=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,101,57,52,57,53,52,
                     45,48,101,97,49,45,52,102,53,54,45,57,57,49,53,45,57,53,
                     99,99,101,49,51,100,101,51,53,57>> =>
                       <<"±xQlT3JuO3TKxCaR8ITCxWhOLcgk815lvouywS5wI3QQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,97,98,52,48,50,52,45,
                     101,52,54,100,45,52,48,56,57,45,97,52,97,98,45,53,52,51,
                     101,55,55,56,51,49,53,55,99>> =>
                       <<"±e1ZzzS6aUKv16Wr+2B9eVtPrZTkSxuN3u/t8UZO5oT0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,48,53,100,52,50,97,56,
                     45,53,101,53,99,45,52,52,49,50,45,57,101,102,101,45,53,
                     51,99,98,48,57,55,51,55,48,57,56>> =>
                       <<"±lqL9qKmrG+Ycn0+FmkchDqMqR58YsKvvK6ms20Y8PWw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,101,98,53,56,54,56,
                     99,45,53,49,54,99,45,52,50,48,98,45,97,50,98,48,45,49,
                     100,55,56,98,102,55,97,100,49,101,52>> =>
                       <<"±x9yDUpuZabVrMYccNbLtZy4I7xUWoU6YbIKoijg8ZC4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,51,100,48,99,100,52,
                     45,98,101,57,56,45,52,51,100,55,45,97,99,50,98,45,50,57,
                     102,51,54,56,55,57,55,51,57,98>> =>
                       <<"±9boT2dx9v8lohCXRuCxrNSt0fXjPwlH+YNkAppwOVJU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,100,97,99,100,54,51,55,
                     45,99,55,52,55,45,52,54,48,57,45,97,54,99,53,45,99,98,
                     54,55,99,52,54,54,55,52,48,99>> =>
                       <<"±42rjbAwbdbDR93ci/dwyt021CaZ9V8ZzEUQBHaSrJdM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,54,48,97,51,48,51,45,
                     55,99,101,101,45,52,54,52,52,45,57,50,99,55,45,51,98,48,
                     53,100,55,52,51,101,54,97,101>> =>
                       <<"±aovANwC6JzKIgBFdHpAJ2N3nHVwI6j5lBGsPo62Sp5E=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,99,50,57,57,53,50,
                     97,45,49,49,51,100,45,52,56,100,51,45,97,51,56,56,45,56,
                     49,102,99,56,99,100,97,51,53,102,57>> =>
                       <<"±+kcv+9uWSAm8z/5JPzcFwFNbi6xTjjklmmZk7gSE6XM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,50,48,55,100,50,54,
                     99,45,57,52,48,55,45,52,50,54,54,45,98,98,57,101,45,49,
                     56,100,52,102,102,100,98,101,97,53,56>> =>
                       <<"±f4EVVcJb5IJLXSn4tMVbQfTVPsuDFm5nzrNXcFLwCrc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,102,50,55,52,98,102,101,
                     45,99,50,51,55,45,52,98,56,97,45,98,50,53,53,45,102,98,
                     49,100,52,51,52,49,97,53,48,102>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,52,100,57,51,51,57,
                     52,45,53,48,56,98,45,52,57,97,53,45,56,102,57,100,45,56,
                     55,101,53,102,51,100,49,101,53,98,53>> =>
                       <<"±f5v/PqkAX3+0ArXD7iv2e0j8nJL9vkioHRXv+SaajC4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,100,98,51,97,99,
                     102,100,45,57,101,56,56,45,52,101,55,97,45,97,56,56,102,
                     45,57,52,100,52,98,55,102,50,54,50,101,100>> =>
                       <<"±HUq6RXKNIWE/aKOK1colcZV1pE6dhckBi5wpH9Q+yQw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,52,54,57,102,53,54,53,45,
                     100,54,53,49,45,52,97,54,100,45,57,54,49,51,45,57,51,98,
                     48,56,49,51,99,55,50,102,57>> =>
                       <<"±ZKIf60ZvHLhCMShUCw6nokoYfQTYU47jmNIRzdBbKpw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,57,51,48,57,98,51,45,
                     102,52,52,53,45,52,57,97,49,45,98,55,56,54,45,97,54,98,
                     98,55,102,100,98,97,54,54,55>> =>
                       <<"±JZs3zOYCyRj2psNQ0VVeXkkM+ffxZ1CyivmN37+XELY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,51,56,48,56,56,55,
                     100,45,55,102,99,56,45,52,49,52,53,45,97,52,101,100,45,
                     53,57,99,50,51,57,102,49,101,97,54,57>> =>
                       <<"±W+9rQovMjKi468bLFCc3XfGjUiFE4FkL9DQeRbODdkY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,50,52,52,99,54,48,49,45,
                     99,53,52,49,45,52,99,55,55,45,98,48,97,50,45,51,53,57,
                     50,53,48,56,56,51,53,100,102>> =>
                       <<"±S+znYcC+EHut4EEYCnvWpuQfoKqAtK+FK+WUaTjwyKE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,48,99,57,97,54,97,102,
                     45,98,54,101,50,45,52,52,54,98,45,56,51,51,56,45,51,101,
                     53,101,52,102,55,102,48,98,102,57>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,98,48,53,48,49,57,45,
                     48,57,49,48,45,52,49,100,53,45,56,50,57,56,45,56,97,49,
                     98,52,57,48,48,50,49,49,48>> =>
                       <<"±mC/3yZva49RdkM3GtDo+Kduv5nfVnu4rEjZa32Ve0cI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,51,97,101,55,50,
                     100,98,45,54,52,51,48,45,52,102,57,48,45,57,56,100,51,
                     45,49,52,100,50,52,51,57,56,56,57,55,55>> =>
                       <<"±N66kKPS5DczZgD+4B8h4qNXxcyocRw4wKyO3QXKVSZU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,57,102,102,57,49,50,57,
                     45,50,56,97,50,45,52,50,101,54,45,98,52,56,52,45,54,56,
                     51,54,98,97,56,98,56,49,100,51>> =>
                       <<"±6bcVLQNVmDbJJ6wyaUiiwDwvyXzBgj+eL1u0ddpkEJk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,49,56,100,98,100,
                     98,48,45,99,56,99,100,45,52,54,49,53,45,97,52,48,51,45,
                     102,99,57,101,53,99,49,101,50,52,49,54>> =>
                       <<"±viRbBQz82tgpI8GEABJBw3egVMBb8z0NR/s5OVMVRyY=">>,
                   <<1,0,0,0,0,17,107,101,121,53>> =>
                       <<25,118,97,108,117,101,53>>,
                   <<1,0,0,0,0,161,98,109,116,95,48,101,48,55,50,49,56,49,45,
                     98,57,102,97,45,52,55,99,49,45,56,102,53,97,45,56,55,51,
                     49,53,98,102,102,50,48,99,55>> =>
                       <<"±DBARJm9bZckV5vW4pDus44jnvuB0tI6+4L/Xegotpk4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,51,97,54,98,101,102,
                     45,97,50,102,52,45,52,52,49,56,45,57,98,102,57,45,48,49,
                     55,97,50,48,54,57,49,99,98,99>> =>
                       <<"±5FX80gDvrPMrNd3wpWB7bFJ9iWGQP27IuaKq9J+huQg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,97,97,101,54,98,99,53,
                     45,97,98,97,50,45,52,100,102,48,45,57,102,97,100,45,51,
                     55,99,102,48,48,50,97,56,52,101,49>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,101,99,55,97,50,48,49,
                     45,97,49,56,50,45,52,97,49,53,45,97,49,97,57,45,99,102,
                     50,51,102,55,48,50,55,98,56,101>> =>
                       <<"±aC3tKcLKooj60HRNBwdN+Ej69H6Px3f5HuOUDg2hPeU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,100,98,56,50,51,50,101,
                     45,57,54,98,49,45,52,52,54,55,45,98,49,101,52,45,52,99,
                     97,101,102,51,100,49,56,54,53,100>> =>
                       <<"±zYEjH6pwLhy2TUoxypTU+j1xwMCfKqapt9tgjQ2Wpv0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,49,54,56,51,99,52,45,
                     51,102,100,57,45,52,54,53,98,45,97,56,98,98,45,56,48,97,
                     102,50,55,57,49,51,98,49,54>> =>
                       <<"±mmvRznmeHFlyLNYHKAaFPXnFS8MVm2F5TOavv0580uQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,48,102,57,53,56,49,48,45,
                     50,53,102,99,45,52,51,53,48,45,98,54,49,98,45,102,102,
                     50,55,55,55,101,49,99,51,102,51>> =>
                       <<"±DmANSt6eDVrG4XBoP5/3eujWfiD3zTpPwtGZmbAoOxk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,55,49,97,51,55,102,53,45,
                     49,101,52,48,45,52,102,97,53,45,97,55,56,48,45,51,97,
                     100,98,100,49,53,102,53,100,99,97>> =>
                       <<"±roGvvnCFyh6HkA0cw5fmdIepbGxrZrSdfZ2AIvK6uis=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,51,98,53,54,49,98,45,
                     50,48,49,54,45,52,53,50,49,45,97,97,57,102,45,54,102,53,
                     56,48,55,55,56,101,98,48,102>> =>
                       <<"±70Z2brCuA59phDQjbxxEEi9cbGHFwNzBi9DQIsXp2Co=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,97,56,101,102,49,
                     53,98,45,49,57,50,102,45,52,51,56,53,45,57,55,99,51,45,
                     99,48,48,102,48,98,97,54,55,50,101,56>> =>
                       <<"±TRhAc5W/TgLx+MiG2aiXyd5FSm3kUw4fnB4/ofGEhmc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,51,53,99,52,56,57,45,
                     55,53,98,56,45,52,97,98,57,45,97,48,49,101,45,54,48,54,
                     48,57,52,49,99,100,51,50,48>> =>
                       <<"±7fY2IUfzpamW3mdm0yw4SLbMRN+M/eeXSdFXgHgvKIA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,51,56,48,98,55,49,
                     55,45,52,49,52,54,45,52,102,100,51,45,56,51,54,99,45,97,
                     52,53,100,52,100,55,52,99,56,99,52>> =>
                       <<"±rxEMjZ9V3nH1f20qY3FMpnKzwSKYp4QEDGJyPWAywcQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,98,100,50,54,54,101,52,
                     45,102,55,101,52,45,52,54,102,101,45,56,48,98,48,45,102,
                     48,97,102,99,53,56,54,99,52,55,52>> =>
                       <<"±iNb70oM2jeh9jTNeXHYb36A7hGFTiELXIMiugVZaUMc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,57,54,100,52,53,53,48,45,
                     50,99,100,50,45,52,99,53,100,45,56,102,97,49,45,57,53,
                     48,48,100,48,50,57,100,97,100,57>> =>
                       <<"±Jj9zg48FwH2lcsuwNWfd8m9jZsqwAGSOc708Fj7qXFo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,53,97,98,51,53,56,45,
                     57,48,50,97,45,52,102,48,57,45,98,101,51,50,45,100,98,
                     48,54,49,98,98,52,100,57,51,56>> =>
                       <<"±Q+92/gEUvsDROGE2PuRqkHOVCHRlgkizL3wDboHHjH4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,100,52,49,98,97,98,
                     102,45,97,52,55,101,45,52,102,56,98,45,57,54,97,97,45,
                     50,50,55,99,51,101,48,56,49,48,56,50>> =>
                       <<"±koDxD5pN+5suHNCFfkMWAm871m0Q3gyjNmlbVS4+wUg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,56,49,97,98,97,49,52,45,
                     53,97,52,53,45,52,56,56,53,45,97,54,52,49,45,52,97,57,
                     51,52,55,102,97,98,56,48,101>> =>
                       <<"±K1ZXl1GgHeN3hmjASS37TwdRCnBTJjVbYu8QQk1odJs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,49,52,57,98,57,52,52,45,
                     50,97,48,48,45,52,48,54,48,45,57,56,100,98,45,50,99,55,
                     54,54,49,50,49,53,56,55,57>> =>
                       <<"±86EUZzbqJsbKFCTuTmbzDw8a4q8oub+bnHEoonGYoww=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,57,53,55,100,56,
                     100,55,45,102,98,98,99,45,52,51,98,99,45,98,97,102,50,
                     45,98,56,54,100,102,99,53,97,98,55,97,99>> =>
                       <<"±iDLj4x8g7HkVJUcwBpWuVDqGirSS50fnaxoFlKoJeyo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,100,97,97,55,48,57,45,
                     56,51,100,57,45,52,55,48,52,45,57,99,102,97,45,97,99,51,
                     53,97,48,102,101,48,97,102,100>> =>
                       <<"±PHgPsPkrSfTIo/eRCssZcB/I/7JRG/BBxYYrAQebkL8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,54,55,102,98,56,97,51,45,
                     100,55,99,56,45,52,54,55,55,45,97,55,101,56,45,48,99,57,
                     53,57,51,99,54,49,54,54,49>> =>
                       <<"±T2sJTRv+X6QRi36UFclmHJkLgBa13EoXKv6lrKsyidI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,53,53,50,98,57,49,98,45,
                     49,48,53,54,45,52,55,56,54,45,97,98,97,50,45,54,53,102,
                     100,52,102,54,55,50,52,55,56>> =>
                       <<"±LxO9tsgD4Nv83doD6FLvLoj4ntmGQlmt8wKBlREKe7Q=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,48,55,51,99,49,50,
                     99,45,54,98,53,51,45,52,102,55,97,45,97,102,56,56,45,57,
                     97,56,53,51,48,52,57,100,98,49,52>> =>
                       <<"±fpa5a49ywRvBewko7fjx/RmmwmfzFBKrrEl4V7OfXNw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,102,50,50,49,101,53,102,
                     45,52,49,99,49,45,52,97,54,102,45,56,53,101,100,45,55,
                     99,53,102,56,51,100,53,56,50,97,56>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,98,52,53,48,52,55,
                     53,45,102,54,54,100,45,52,55,100,48,45,98,97,100,53,45,
                     48,98,102,48,49,102,102,51,49,48,51,52>> =>
                       <<"±sFH8OvYDzW3Z498gKp2wW2dnJSE5tV8lIE6ly8SmIWc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,50,53,55,56,52,55,45,
                     51,55,57,49,45,52,98,100,102,45,98,50,99,100,45,54,102,
                     97,99,101,52,99,99,51,49,51,55>> =>
                       <<"±xK9+20eiGKybXQ9bA9xAGYesk569Qo5A1LkHny7DHT0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,99,52,49,50,54,102,54,45,
                     51,51,97,99,45,52,99,97,48,45,97,97,51,97,45,57,51,52,
                     99,48,98,54,97,51,97,99,98>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,54,98,50,49,57,50,
                     49,45,49,49,50,100,45,52,99,100,100,45,57,101,97,102,45,
                     100,98,57,102,100,101,98,55,100,54,101,49>> =>
                       <<"±HUHjHHLu2iy/DZ/BzMzUATucs7tDikzYBupBIIMpLWI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,102,49,100,55,102,
                     98,57,45,57,98,57,100,45,52,57,52,53,45,98,48,97,56,45,
                     54,55,53,101,100,100,101,98,52,99,98,54>> =>
                       <<"±2y0Cz8jwCpKxUTnyaAfg09Nuzwp9BffqkuXAqcwN9+g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,57,53,50,48,100,49,45,
                     51,102,98,55,45,52,51,100,53,45,97,98,56,52,45,102,56,
                     49,56,56,99,102,97,98,101,100,48>> =>
                       <<"±aYk+MjLAlA1IYtvalGY1X3FHes5K1tuVqj3okg+Q4QQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,102,99,98,52,53,54,45,
                     98,99,97,51,45,52,52,97,54,45,98,50,97,53,45,99,49,55,
                     53,50,97,97,52,98,57,56,101>> =>
                       <<"±mCSjxLjSgJ561nVHUTfpdNgklzvS0cpV5iKZxlwBOKo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,51,56,54,98,48,53,45,
                     99,50,98,54,45,52,49,56,50,45,97,100,102,52,45,51,101,
                     50,54,51,98,50,100,56,56,97,52>> =>
                       <<"±QVDTN0XlQqPOO2VKB6AIEibmAKNtWbjzKpFlUlZkx34=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,99,57,99,102,97,54,45,
                     97,100,101,48,45,52,50,51,98,45,56,48,102,101,45,50,49,
                     50,49,97,56,98,99,55,57,53,50>> =>
                       <<"±3bpUmrRESqXZvZYojiS5GwlSbnATuuPjGu8vhO4Knl8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,52,57,49,50,50,56,
                     54,45,102,100,52,48,45,52,55,49,101,45,97,55,52,54,45,
                     56,100,53,102,52,48,51,101,52,97,56,56>> =>
                       <<"±gzU88QiYMwommihmmk/ZaG1JUppuHhC0+I517DR/Jbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,53,48,49,48,98,102,45,
                     57,97,57,102,45,52,101,101,54,45,57,99,51,49,45,101,51,
                     52,50,51,99,102,51,52,56,53,50>> =>
                       <<"±CmFZUA2vtzAp4TWRDt/bwSqHPkWTyimc5IOvGpU45EQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,102,48,51,97,55,54,56,45,
                     54,49,48,102,45,52,101,52,100,45,98,97,51,57,45,99,97,
                     57,56,57,99,55,53,99,97,98,53>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,54,56,51,48,52,
                     101,102,45,50,52,101,53,45,52,97,99,53,45,57,50,98,54,
                     45,101,48,54,97,57,56,98,100,101,54,102,52>> =>
                       <<"±jGZujtxsErVJh5sim+Z163ORLImc2VwpN6i1w+0fGp8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,102,55,101,102,100,55,97,
                     45,97,55,98,102,45,52,51,52,98,45,98,55,52,50,45,48,53,
                     100,48,55,48,57,57,49,48,53,57>> =>
                       <<"±qChjY7ceuu5+/ILt9NcvpJze7wgcnlFlQ/ewRBa3JMs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,98,56,49,57,98,49,55,45,
                     52,50,52,54,45,52,52,50,52,45,56,98,51,51,45,102,52,56,
                     53,101,55,53,101,55,100,51,53>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,54,98,51,54,101,53,48,45,
                     102,54,51,56,45,52,97,48,99,45,98,52,54,55,45,101,49,48,
                     99,52,55,55,102,54,48,53,55>> =>
                       <<"±ahVNWkELLTw2C9pfa3qAwlKo14Z+BSRkBT/KiZlnvY8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,51,53,55,48,98,54,45,
                     55,57,55,50,45,52,49,57,56,45,98,99,52,51,45,50,100,48,
                     49,52,101,99,97,100,102,50,99>> =>
                       <<"±VPVpPZuW5Jx5w3xDQly3ilh38rLyXpB8qAK1+mnsr+E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,101,56,99,54,50,101,
                     45,57,50,102,52,45,52,102,52,101,45,97,98,101,54,45,49,
                     52,55,99,50,50,53,54,57,100,53,101>> =>
                       <<"±uTjDDA048MBsbTgK3xe0dTHAWGobmU88FtB41eeHa+Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,57,101,53,97,48,98,52,
                     45,101,99,97,57,45,52,101,53,97,45,97,48,101,102,45,49,
                     102,100,55,57,102,101,57,53,97,57,54>> =>
                       <<"±bmmRaeGT+blx7qgoD8JWQ/rvsL/M1QrOU1/sOUohnOI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,52,102,49,99,50,52,48,45,
                     98,50,97,53,45,52,102,49,98,45,57,100,102,55,45,52,54,
                     54,56,54,56,57,97,56,56,53,51>> =>
                       <<"±XvK+xyuxObsrUEE8lNRv8LdPUnMU62JD2/6EkmGpYfs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,102,101,55,54,50,51,
                     45,101,55,57,52,45,52,51,57,48,45,57,100,102,56,45,56,
                     101,48,51,48,57,57,100,98,49,100,97>> =>
                       <<"±gMzDnZSlWpqKx4/oi9pgO+y/0Mu3/5oXfAgOoWQ/Wos=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,56,102,102,55,101,56,57,
                     45,55,99,55,51,45,52,53,102,98,45,97,54,99,99,45,52,54,
                     52,98,50,100,97,101,49,51,101,98>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,55,101,56,98,53,101,50,
                     45,56,97,52,100,45,52,97,55,49,45,57,51,102,102,45,53,
                     102,50,97,49,54,54,51,54,54,55,56>> =>
                       <<"±NaG0vjGdkWnAkqbVTVbvcEvHuGUrbVH1PXVohd4Cb1M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,98,50,48,50,56,98,48,45,
                     54,99,100,97,45,52,49,57,55,45,57,56,48,56,45,100,49,52,
                     53,97,99,55,50,51,51,51,51>> =>
                       <<"±ql5JD852tHVknLpjv5XvgekvE1F7Z8Etgow65nxMNAc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,51,99,48,97,50,48,
                     102,45,55,53,53,56,45,52,51,97,99,45,97,49,98,49,45,49,
                     50,54,55,53,51,53,57,57,52,98,57>> =>
                       <<"±6T84BpRQ4eDmunPlWV+KbrUIdgVWmos7goX/easzPgU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,56,98,53,57,50,49,55,45,
                     53,99,97,97,45,52,53,48,98,45,97,50,50,53,45,49,50,101,
                     98,49,101,50,52,99,48,51,50>> =>
                       <<"±KAOW45Pn7Jit/i2DUUakvSPmlHqPKPU7tZfeMc2h4U4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,99,57,48,102,56,97,
                     45,101,97,57,101,45,52,98,57,98,45,97,101,97,56,45,97,
                     100,50,57,51,101,51,97,100,50,52,57>> =>
                       <<"±QEFw+LT2b2zMlLD6qSgY9SFLBuPNtpc/OSee0uwuJVM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,48,54,48,51,55,56,55,45,
                     100,52,101,98,45,52,54,48,55,45,98,100,54,49,45,49,100,
                     52,98,56,52,51,97,56,48,55,53>> =>
                       <<"±cH0sRae9Hb+ItHKRDRjtyHejj4j7hTdjslaDa6Fy4dA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,99,49,53,52,57,101,48,
                     45,54,49,48,54,45,52,57,54,57,45,57,52,97,55,45,53,99,
                     97,97,54,51,48,99,54,56,53,57>> =>
                       <<"±barUp8IxAHFn33MngCZkptdUFBTk0XiYthyPyICPN/M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,101,50,102,56,51,53,
                     45,51,55,101,53,45,52,50,55,98,45,56,99,51,57,45,99,51,
                     97,54,52,48,48,48,53,52,57,54>> =>
                       <<"±TaO51KDXk0XBZF1VTCK+oFk887NqO4iNGEmQSWVFegs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,49,56,57,52,52,49,45,
                     97,51,50,102,45,52,51,48,50,45,98,100,51,54,45,52,54,
                     100,102,99,102,56,101,97,99,57,50>> =>
                       <<"±W5XbAAbMPVZSh96HqzV0q8QVvNyvq3mmAC/PWX17Rzk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,97,57,49,52,52,56,50,45,
                     48,101,102,50,45,52,102,52,102,45,97,51,98,101,45,100,
                     97,50,50,49,52,51,98,50,55,99,55>> =>
                       <<"±cf0olaJR48pEFtbATpW4BXkb/eW9DGZHxu74IAf5TWQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,51,55,102,98,56,102,
                     45,99,53,49,53,45,52,57,102,52,45,98,101,102,56,45,55,
                     101,99,53,100,101,53,57,57,56,57,101>> =>
                       <<"±EZH7SL7C1Tph6cAhSYZwxlcFDnqy79/mXnQz+l9K5lA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,56,53,51,54,54,51,
                     55,45,54,50,56,56,45,52,51,101,54,45,56,55,54,56,45,102,
                     99,101,57,102,48,54,56,102,48,52,49>> =>
                       <<"±whiIc7q3QNMGfJ8rAvikLIOrzBtCA5ilDmJGwThHMAI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,98,99,49,50,48,98,45,
                     99,57,55,50,45,52,53,48,100,45,97,99,55,56,45,55,100,49,
                     48,51,100,97,97,48,97,101,48>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,55,55,54,53,102,54,48,45,
                     57,57,100,51,45,52,100,102,101,45,56,100,54,56,45,55,
                     100,56,48,50,49,51,49,98,50,52,102>> =>
                       <<"±nTo6EEHhSolq2V7XL3EN5OPrcyXrJdr89aLnnWQzEbE=">>,
                   <<1,0,0,0,0>> => <<0>>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,57,56,51,55,52,51,
                     97,45,56,55,52,48,45,52,50,56,48,45,98,53,53,50,45,101,
                     57,99,56,51,97,101,56,48,102,97,49>> =>
                       <<"±hQ4XiPfSBYZ5l0stv4AhNhlsSyH54x+Ug6OuguOk2kE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,52,48,101,55,102,98,
                     45,50,100,54,101,45,52,50,52,48,45,56,57,49,49,45,53,57,
                     49,53,55,99,50,100,49,55,52,102>> =>
                       <<"±pab2H88FPK8JiA1m8bm/SQWuNqUDCfwkcBQtInypSds=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,99,102,57,99,57,57,57,
                     45,98,97,51,98,45,52,57,102,101,45,97,53,51,57,45,55,98,
                     53,56,97,57,57,100,101,97,49,49>> =>
                       <<"±AIym2DZmbcjgwcwZv65/+VZJLtwOPi3yIl3VllQ5Pr0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,57,48,50,56,100,99,53,45,
                     51,50,49,52,45,52,51,99,56,45,57,52,54,50,45,55,99,99,
                     55,97,52,102,100,57,52,54,55>> =>
                       <<"±BCyjaCqEzQWXRKEtRHP5Bp5x6fhAVTAmYrsYGADK1f8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,102,100,48,48,97,100,52,
                     45,100,98,100,100,45,52,102,48,101,45,56,100,100,48,45,
                     53,54,98,51,99,97,99,48,54,51,102,50>> =>
                       <<"±+zyzn3PZydn0YXtQFKK7MiaoefDcMEJSSudDB+PXGvs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,48,54,53,98,51,54,45,
                     99,50,99,54,45,52,48,98,50,45,97,54,56,52,45,49,97,54,
                     57,57,50,97,101,99,54,56,48>> =>
                       <<"±0XlcNPAsZ3Q4CYnEk1xN6CLitjH41f3GF65fD3YsynY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,56,52,97,99,52,50,45,
                     99,52,48,48,45,52,52,54,100,45,98,50,48,57,45,57,99,100,
                     53,100,52,53,52,100,97,57,54>> =>
                       <<"±0ix0GXq+dN1oyMTfRzm1BwVcqCmoaQFl7M/19T8IzzA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,55,57,50,48,48,99,45,
                     99,97,100,48,45,52,101,57,98,45,57,56,50,98,45,54,53,56,
                     50,57,54,99,51,57,99,98,100>> =>
                       <<"±4KYjC6b3E3mdu/OIrLGf2BYwhsLTTsRM9jjOk3MJ7lE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,98,101,102,54,97,99,
                     45,53,52,54,49,45,52,57,98,50,45,57,55,99,49,45,48,50,
                     53,99,56,54,56,48,49,57,101,50>> =>
                       <<"±Qo0ixkK6JGyn5i45FKHuURhr8N534hFttv5usi1dJ10=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,57,102,48,100,51,97,
                     45,56,57,51,50,45,52,48,99,101,45,56,53,99,53,45,57,97,
                     101,99,49,50,52,54,100,56,100,97>> =>
                       <<"±dIpXR95EikZemVjbYpWHvKcJBaNPhyzwt2aTJuPqFmA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,56,55,50,101,97,56,
                     48,45,57,97,49,102,45,52,102,101,54,45,98,99,53,98,45,
                     98,99,52,100,54,57,102,101,56,57,49,98>> =>
                       <<"±/CJ4xQeiXwDL94p6OH2VzuHGjdDIM+WViJ1SspYkqKk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,98,100,102,56,56,
                     51,100,45,51,48,98,48,45,52,48,50,50,45,98,97,52,56,45,
                     50,102,97,52,97,100,101,99,53,56,97,98>> =>
                       <<"±P7WQEvd2gwfmX2M4prafuMwlcTjOlq+2uu0WKuSuMjU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,48,99,54,49,57,56,50,45,
                     101,98,57,52,45,52,49,48,101,45,98,48,99,98,45,49,55,50,
                     48,54,102,49,56,97,55,99,55>> => 
                       <<"±rpodstZ6VeER7J4iURLn5Zf+IZJVjLMZHD2dkqnjdi0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,55,55,54,97,57,99,45,
                     100,57,97,102,45,52,55,55,102,45,97,101,98,99,45,52,53,
                     97,49,97,101,97,100,98,54,49,48>> =>
                       <<"±MN1YOg/5a39fOMnHEnTmrWJzYEWpkV+7axH9SjllowE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,53,99,99,53,98,98,45,
                     48,51,48,54,45,52,49,98,48,45,56,97,56,102,45,51,49,50,
                     51,55,97,100,98,53,56,100,55>> =>
                       <<"±2JdZkFDkScsL5FzHpWrlr7yZ/dMXAOWM4siu+nVgBQI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,50,52,56,48,56,51,45,
                     102,53,48,98,45,52,56,102,98,45,97,55,100,98,45,102,57,
                     99,48,57,56,49,50,101,50,51,53>> =>
                       <<"±V7Yakm5qXI9CIqqBrONNAq+xqsN1vqidyejEZ2zYwKE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,101,55,55,52,97,57,45,
                     57,97,97,102,45,52,57,101,57,45,98,100,99,100,45,53,51,
                     49,55,102,49,100,50,54,57,98,98>> =>
                       <<"±48sSQOIe4Obi7HCcd6YZgX37Fa0L03V+lqV5xwJp6mI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,101,102,56,101,56,
                     51,98,45,54,102,98,100,45,52,49,55,57,45,98,51,52,52,45,
                     98,100,56,55,101,48,102,48,102,48,49,99>> =>
                       <<"±2o+ye8flZ4xsZiqGNJcvwmJmN58CLNEFkHNOBYbcwIM=">>,
                   <<1,0,0,0,0,17,107,101,121,48>> =>
                       <<25,118,97,108,117,101,48>>,
                   <<1,0,0,0,0,161,98,109,116,95,48,102,52,56,49,55,49,97,45,
                     52,54,51,54,45,52,50,57,54,45,98,56,49,53,45,101,50,54,
                     52,52,56,56,51,101,54,53,102>> =>
                       <<"±caLDQCdRaxwROMYfPMrIVPVEPBn5aSOb6r9ZMIHxyh0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,56,48,100,98,101,52,99,
                     45,50,52,56,102,45,52,48,50,56,45,97,51,100,99,45,56,55,
                     101,50,50,99,48,102,97,52,55,56>> =>
                       <<"±T2izcwRvVowKTECtxP9al8JyZL4UV1YIPKvNV1U67zo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,56,98,100,100,53,
                     54,56,45,56,52,53,97,45,52,49,98,54,45,56,98,97,100,45,
                     55,57,48,52,53,99,102,57,53,101,101,100>> =>
                       <<"±i0CnqRXriixLaQjUGoiocrmO4r8/oOCublaNEzYJYP8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,50,52,50,52,101,102,
                     45,48,101,102,97,45,52,57,51,50,45,56,50,53,56,45,102,
                     102,100,100,101,97,56,54,49,97,52,97>> =>
                       <<"±44PT2goXuX94lfhlcf781CycTVcjRAGpBEZMBzLloWQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,51,102,49,52,57,48,
                     45,100,99,49,56,45,52,48,98,101,45,56,99,100,52,45,53,
                     48,51,54,97,50,49,97,52,56,98,100>> =>
                       <<"±r6B2WC5qxhFLWs/HVFEHrvQi6by8ACaOV5uskPFV8Dk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,51,99,51,101,101,53,
                     45,51,98,99,55,45,52,99,52,53,45,56,100,54,57,45,50,98,
                     52,53,53,102,53,100,56,102,54,48>> =>
                       <<"±dGnv71f+D2wVvjEeFx/d1JXHYb335vzeoQEDz1Ot3L4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,53,97,50,56,57,98,
                     48,45,99,57,51,48,45,52,55,100,56,45,97,49,97,54,45,97,
                     52,54,55,102,56,98,57,56,99,101,99>> =>
                       <<"±MU9StyYdmFsusISja4kXt2PABmK3rVAYXVQaYCxEdpQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,48,48,49,49,98,54,45,
                     56,97,101,52,45,52,97,50,99,45,98,56,51,48,45,98,57,98,
                     100,99,50,99,98,102,49,49,102>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,48,101,98,49,49,54,45,
                     55,52,52,55,45,52,50,53,50,45,57,54,99,98,45,52,56,98,
                     56,52,50,99,57,50,50,51,55>> =>
                       <<"±GoPtjNUcFQ9KSq3o5OpRCFTZ7XsxYg9Lbp008lvcCVk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,53,49,99,49,56,98,53,45,
                     97,53,55,98,45,52,102,101,49,45,56,56,98,102,45,101,48,
                     97,52,102,48,53,98,49,102,49,54>> =>
                       <<"±2CrQxLN1sGHpQP3uoSFNFg/0wXw0Oyfy3kAUk3VozXg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,99,99,97,100,48,53,45,
                     48,52,55,52,45,52,55,50,101,45,98,98,56,99,45,100,52,
                     102,97,48,98,98,100,53,101,98,51>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,52,99,57,101,52,
                     57,101,45,52,101,53,102,45,52,57,102,48,45,98,101,101,
                     49,45,100,102,56,49,97,97,98,55,57,55,55,99>> =>
                       <<"±5Mn8rck+75aoEqW58z+VVLPjxkKwlzpXcVOIqPQW5yo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,55,100,102,53,56,97,
                     45,49,50,101,101,45,52,50,52,99,45,57,97,57,102,45,101,
                     101,55,51,100,98,50,51,102,56,100,98>> =>
                       <<"±MQqcnLskNX/9mo6Hoqxsf9gqA3xV7SGDl61IAeS9tJE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,51,100,57,99,50,54,49,
                     45,100,98,99,50,45,52,54,102,52,45,97,55,53,54,45,97,
                     100,52,102,54,49,55,54,100,51,98,56>> =>
                       <<"±sJ8MS4w3BT/KFY6FOTmGegaZux0az9pJ+07w1jqvV4w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,52,55,49,55,102,99,
                     101,45,54,56,102,99,45,52,54,51,50,45,98,50,97,98,45,52,
                     102,99,99,97,97,50,55,49,56,102,55>> =>
                       <<"±/N9jRH9UxWSXH2UdoiufG8IjdJ8UebYSj8ZU5KcgRXs=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,49,51,48,98,101,
                     54,49,45,55,53,52,52,45,52,99,52,48,45,97,49,101,49,45,
                     97,102,57,48,54,57,56,55,102,100,99,101>> =>
                       <<"±8Jx8MW7KlJRL91wk8awDNYdxCRvLi5HSqdKRVHJ25tk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,99,55,56,49,102,48,51,
                     45,102,51,101,49,45,52,53,101,56,45,57,99,100,97,45,52,
                     57,101,97,102,52,99,102,54,101,53,53>> =>
                       <<"±aQQaVsaIfXPuZ6L10doOdUZRMmZacYYUVpAOja5RbWQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,57,52,52,97,48,98,
                     100,45,102,51,50,99,45,52,97,51,53,45,57,99,53,55,45,48,
                     99,57,48,101,100,56,53,53,51,54,98>> =>
                       <<"±2NJcNIxJGZae4EkFAd6+0lv5VWxGH4KU6DlfrC8gBDQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,101,50,55,53,50,101,53,
                     45,99,52,53,55,45,52,97,57,98,45,97,53,100,55,45,101,52,
                     100,57,57,48,57,54,100,55,53,52>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,98,55,53,101,100,53,56,
                     45,51,57,50,55,45,52,53,57,98,45,98,51,55,98,45,98,100,
                     54,99,99,51,57,97,51,49,97,51>> =>
                       <<"±1PBXf0EQTnXqwT984EpbiymLko9KWbKq+5fHRXa1a2w=">>,
                   <<1,0,0,0,0,17,107,101,121,57>> =>
                       <<25,118,97,108,117,101,57>>,
                   <<1,0,0,0,0,161,98,109,116,95,53,49,57,52,50,50,99,52,45,
                     97,50,56,55,45,52,99,55,52,45,98,100,55,52,45,57,48,55,
                     57,50,54,55,102,97,97,100,51>> =>
                       <<"±bccg6bqQL1bs2Zo5YhjgBuTJoqAq1ZkOOMPNN3pNfYc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,102,54,99,99,97,98,51,45,
                     54,51,56,50,45,52,50,56,56,45,97,48,57,97,45,57,97,102,
                     48,57,48,49,54,101,53,52,48>> =>
                       <<"±ohW1A9dYcElp0qpPj2l4U1gKMJwJogPPmf1uBh4ncLs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,98,54,102,53,49,100,54,
                     45,102,57,55,55,45,52,99,53,51,45,97,101,56,98,45,56,
                     100,53,99,51,49,102,101,57,52,52,56>> =>
                       <<"±9vYhfoVUBMME7UEkCnsWlseHX+NoTcUb4Lw9l9HWwPk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,57,98,56,56,100,54,48,
                     45,50,102,49,100,45,52,49,54,52,45,98,49,54,48,45,51,98,
                     101,56,97,101,52,57,100,97,48,101>> =>
                       <<"±Dlq41AIPGaEdhyNUbqnllY4q3sMNGMwqITKbBGDARZg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,55,57,56,51,56,51,
                     57,45,54,53,102,57,45,52,97,48,98,45,97,55,56,100,45,
                     101,53,53,53,98,51,50,52,57,57,98,53>> =>
                       <<"±IFRH1XFc1xOKiP1Wbr1AOe4mXFr5lKWMHISSXhLM0D4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,53,98,99,97,51,101,99,
                     45,57,49,57,51,45,52,51,98,50,45,98,102,101,54,45,101,
                     52,56,102,52,98,48,97,101,53,55,50>> =>
                       <<"±/uQpHSzM4EgURHxnzy+H6wbZcn/y+ZfWqOOb59pM7pg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,49,52,54,49,50,102,45,
                     53,97,99,56,45,52,52,100,57,45,97,54,54,51,45,56,102,
                     101,98,48,57,102,102,50,102,53,55>> =>
                       <<"±+HBEN1y5a0Sb3DU4mkuf32GoEKGCm9TvbniYviCHoHI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,57,98,97,53,51,102,54,
                     45,102,54,53,48,45,52,98,98,99,45,57,102,99,102,45,101,
                     54,100,102,99,51,98,50,55,57,56,54>> =>
                       <<"±ARyEwMB3hed6LqbgC375R2GUfbQspxCrL+anvM+jTOE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,57,101,55,101,97,53,
                     45,55,101,54,55,45,52,54,101,100,45,97,53,53,50,45,101,
                     99,52,54,49,102,51,97,101,54,54,55>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,55,101,50,49,101,50,
                     45,55,57,50,50,45,52,57,98,48,45,56,100,99,100,45,48,54,
                     57,57,52,99,98,100,102,55,48,53>> =>
                       <<"±2BhB12NAFvOwHmyO4VH/3Y9KhIvMJurg0SdAFYpXvBc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,53,55,99,101,54,48,
                     45,52,101,102,97,45,52,55,102,54,45,98,50,55,55,45,54,
                     100,50,57,50,101,98,53,53,98,99,51>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,49,100,49,54,99,52,101,
                     45,53,100,54,97,45,52,99,57,97,45,56,57,50,101,45,99,57,
                     100,56,54,56,48,52,57,97,102,48>> =>
                       <<"±+ahuk7ht+G730hFLIAd3Eio5JCUiY/55Un0lbDN1t1Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,100,51,51,99,57,57,98,45,
                     53,102,97,98,45,52,101,56,49,45,97,55,57,55,45,97,54,53,
                     50,50,48,49,53,57,102,57,101>> =>
                       <<"±hzb1oUrtrBgbVbwniHhnrWRFILc5kSHZngJCs8OsYGU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,49,53,97,52,55,48,45,
                     56,97,97,52,45,52,56,57,54,45,97,48,102,97,45,51,52,97,
                     99,53,51,57,102,51,57,101,97>> =>
                       <<"±MfIT9CdoQqswnqgKLOSB4vymImc84RgCG0NV96b6o3M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,100,48,57,100,51,97,51,
                     45,100,102,102,102,45,52,56,49,56,45,56,55,98,100,45,48,
                     52,52,56,99,51,55,53,48,53,99,57>> =>
                       <<"±fe4BqmsYwbzkg2w81SKdyLPs1D4QfdYlucd06cWx9UQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,48,55,101,57,48,49,54,45,
                     51,102,98,97,45,52,57,49,52,45,98,56,56,51,45,56,49,57,
                     56,55,52,54,51,102,55,57,49>> =>
                       <<"±JMpKKj25NVi5s/duqtElBWZiW75flSzqYRmiIALmgxU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,53,56,49,55,53,53,53,45,
                     100,48,48,54,45,52,55,97,51,45,56,49,50,53,45,51,100,57,
                     100,50,50,53,57,51,99,56,100>> =>
                       <<"±PHgPsPkrSfTIo/eRCssZcB/I/7JRG/BBxYYrAQebkL8=">>,
                   <<1,0,0,0,0,17,97,108,97,50>> => <<21,98,97,108,97,50>>,
                   <<1,0,0,0,0,161,98,109,116,95,48,52,101,97,53,97,101,57,
                     45,51,54,54,54,45,52,99,99,48,45,57,55,50,55,45,55,48,
                     55,99,57,51,49,52,98,102,53,55>> =>
                       <<"±ocOh0mlFxeFWl76KlT3Rlj+e50ejf/1WksTUtKdKnLY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,50,57,54,53,52,49,
                     57,45,54,101,52,48,45,52,57,48,102,45,56,51,50,55,45,49,
                     50,99,99,101,51,50,99,102,102,50,50>> =>
                       <<"±NnvRVK6xX+qscAte4k0kOM/rfnVQjVFTOc7xWr0Vp5w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,55,51,54,52,52,97,56,45,
                     53,54,102,48,45,52,54,100,48,45,56,54,99,49,45,56,99,52,
                     50,100,101,98,56,101,98,56,49>> =>
                       <<"±KcRG3SoYxlR6C9EbAMwSsdJI73TwTqhfbRIkH46WlaU=">>,
                   <<0,1>> => <<191,1>>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,100,56,98,52,53,57,
                     56,45,50,52,53,55,45,52,56,53,56,45,98,99,51,51,45,50,
                     53,48,48,57,98,56,101,50,52,57,101>> =>
                       <<"±g72msdYQqwafhXhhSoRmFc3rd+Z7qsz+SGDPdwzvvNI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,102,54,102,52,49,101,48,
                     45,49,52,56,56,45,52,49,52,99,45,57,51,97,97,45,99,54,
                     101,57,53,98,98,55,51,101,101,98>> =>
                       <<"±s8NQYcNajZx8AEAmG/qvqTg5Kj4QMTl8ongTV//lc6c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,56,100,97,97,49,98,51,45,
                     57,49,56,48,45,52,98,55,51,45,57,101,57,57,45,98,57,57,
                     102,48,52,50,51,100,48,57,49>> =>
                       <<"±XXcZqGgW277urOzSwTuamzYs9LAeXGD2RYQZP0OJCXw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,52,54,57,53,57,97,45,
                     55,48,57,48,45,52,55,50,101,45,56,97,52,102,45,53,50,50,
                     100,49,49,101,97,97,99,50,48>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,56,54,98,56,50,99,45,
                     100,53,52,55,45,52,50,100,97,45,97,52,101,53,45,51,102,
                     54,50,99,102,98,50,52,56,101,56>> =>
                       <<"±yiQXTaxkd/Zt+KUexajuadpyDHDE7f74D9JHZ8/04os=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,49,51,57,102,53,102,101,
                     45,48,57,51,102,45,52,52,97,55,45,56,55,49,50,45,57,52,
                     98,50,50,101,97,99,100,55,101,102>> =>
                       <<"±+NX9RbrqIuulhVbwZljLIOcpmfyVloDl5GTUHRvxlIA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,55,102,51,98,53,49,45,
                     57,50,50,98,45,52,100,50,99,45,98,49,48,97,45,57,55,51,
                     48,97,97,56,54,57,100,99,48>> =>
                       <<"±ime2iR3hpVuNefcdCe/g4TAp4Ry/j2ZfUcA1ssqVqME=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,50,97,53,51,98,56,45,
                     54,97,52,53,45,52,51,48,57,45,98,51,50,98,45,97,102,55,
                     100,57,53,102,57,50,102,53,53>> =>
                       <<"±Nyh8YOFC4OAVg+SWDx5hvtYFr0bCDn5josmb2DlaAUk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,49,56,98,55,100,48,56,
                     45,55,48,102,53,45,52,48,100,54,45,97,102,101,57,45,99,
                     55,51,99,49,51,55,97,55,102,55,53>> =>
                       <<"±gqOlUvGQSx2cJWdoQ3a0c3pFqHpRu68vqdGvPdsVBgA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,50,57,101,97,56,52,101,
                     45,50,54,49,52,45,52,53,99,97,45,97,57,101,97,45,51,100,
                     48,52,98,56,49,97,51,101,56,99>> =>
                       <<"±c9xzy+H8cVzYlLfn+4XFKbZCnPHU29cQnRiD4NJVGXQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,102,98,52,48,53,97,50,45,
                     98,54,53,102,45,52,98,54,49,45,97,54,98,97,45,52,50,51,
                     56,57,99,97,54,50,56,102,52>> =>
                       <<"±a6Ft56sbOO+yok50Zr8Kc9xeHpcA9dBhF8TbFZWxt0A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,51,99,97,50,55,101,45,
                     54,102,54,52,45,52,101,55,55,45,57,97,98,101,45,55,56,
                     57,51,55,49,52,54,100,51,101,54>> =>
                       <<"±lNhFv9DDej0wA28XjkwwWuYFSqBamSKV/DsF/kdHup0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,53,49,50,49,97,97,99,45,
                     101,101,53,53,45,52,55,50,98,45,98,100,51,98,45,49,55,
                     55,97,49,52,48,53,102,100,97,101>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,48,57,51,100,98,49,45,
                     97,57,98,100,45,52,50,57,98,45,56,97,101,99,45,100,98,
                     55,100,56,102,54,49,57,101,51,101>> =>
                       <<"±TrE2owBuOtaQaT1Ab2FnxC5897Ber7yWXDN5j3WvkTQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,51,51,49,52,101,55,101,
                     45,101,102,53,102,45,52,100,53,97,45,56,56,53,49,45,98,
                     100,52,101,53,50,57,56,100,52,102,56>> =>
                       <<"±FNHIdiydR5Td48osEMyh+qvv0C4JlVRkNENesz/0Ao0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,49,98,48,98,55,100,49,
                     45,48,98,52,100,45,52,101,102,57,45,56,52,97,51,45,48,
                     48,100,54,101,54,48,102,49,56,49,55>> =>
                       <<"±NNJFVaPZ5yW4eG829wBXhGgm+FufhlTrFaWgA2PXw88=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,52,49,98,52,102,102,102,
                     45,100,101,101,50,45,52,100,101,99,45,57,101,53,49,45,
                     48,52,102,57,51,100,102,102,50,48,49,100>> =>
                       <<"±90Jl9j2Dhb4EGoeI92GnNpKkqit8aiCWSpxYDch0KTA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,98,98,49,49,98,97,97,45,
                     54,50,50,53,45,52,102,97,98,45,56,50,97,99,45,53,50,54,
                     99,99,53,51,51,56,48,53,49>> =>
                       <<"±2EIDwrhrdpXL4YyYYbPgC6uDjdIRD0/Zt9ey7T1d0/w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,56,54,53,98,56,98,54,45,
                     100,100,55,54,45,52,52,98,50,45,97,56,54,55,45,98,54,48,
                     49,100,49,57,102,99,52,97,98>> =>
                       <<"±N9u7ZWmgpLJ17U/N1PQExjWbFFq01VlD/nP4Yd/QwUI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,53,99,55,49,98,98,
                     55,45,98,49,100,101,45,52,101,52,55,45,57,100,51,51,45,
                     51,57,99,49,55,51,50,49,55,102,52,48>> =>
                       <<"±xsVvSBdi6po0+rts8QNRSglPRxcU2ggpgTQGRYHO/e4=">>,
                   <<1,0,0,0,0,17,107,101,121,54>> =>
                       <<25,118,97,108,117,101,54>>,
                   <<1,0,0,0,0,161,98,109,116,95,48,57,48,49,49,97,57,55,45,
                     48,97,54,49,45,52,48,56,102,45,56,51,57,50,45,54,100,56,
                     98,54,55,50,102,99,55,54,100>> =>
                       <<"±7RHkgczP23TQ7fqWZdXh/5N4T/mowarhH75cXAE2sKM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,51,57,102,53,51,99,51,45,
                     102,54,48,49,45,52,52,98,101,45,98,48,48,57,45,99,57,
                     100,98,100,102,52,52,98,56,101,101>> =>
                       <<"±gKAZ444YXfkFyCFTid08p8Bo2lCFa75yMYVY36t/5Us=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,101,56,100,55,55,101,
                     45,99,53,51,97,45,52,101,101,52,45,57,99,97,56,45,54,56,
                     53,53,98,55,99,97,97,97,97,56>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,56,51,54,99,55,50,45,
                     50,53,55,53,45,52,101,102,99,45,56,55,50,56,45,98,98,52,
                     98,52,48,98,57,102,100,101,57>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,100,48,102,48,97,99,54,
                     45,48,98,50,53,45,52,49,56,56,45,56,53,50,99,45,55,56,
                     56,49,57,57,50,98,51,50,57,51>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,57,57,51,50,52,97,45,
                     49,49,97,51,45,52,51,53,48,45,97,53,51,52,45,97,49,100,
                     99,56,98,53,101,51,100,57,55>> =>
                       <<"±7uXcS8cnhLz3WlavyIyF+/Z9mjlMFbIhQAROjKUplRE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,98,51,100,98,99,56,100,
                     45,98,53,99,51,45,52,57,50,101,45,98,49,55,50,45,99,101,
                     56,100,48,57,50,48,57,54,99,100>> =>
                       <<"±b5LKAERPtTFrdkss23t+M3Wh+R99qaHpiRbkZTmKEHw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,102,98,49,49,55,98,100,
                     45,55,57,57,48,45,52,48,102,97,45,57,56,55,97,45,50,48,
                     57,52,50,55,56,49,52,51,101,57>> =>
                       <<"±FEFvvVQ9PWn11g4MTQSsqSqUG2QZrQdWYpRTtzcuJxY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,100,49,57,51,51,102,
                     45,52,100,56,53,45,52,56,97,97,45,98,56,49,102,45,55,
                     102,101,98,57,48,53,55,48,52,102,48>> =>
                       <<"±lFGRVM7EzFfsiV+p0tRPa3Xfqab8on10L6oE+BLPb5o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,56,97,57,49,97,50,45,
                     98,55,56,99,45,52,98,57,55,45,56,55,50,101,45,100,54,48,
                     98,49,97,50,97,53,100,98,97>> =>
                       <<"±T41CRDNUknrYYrnTOM/dXuR42vxSDibblV3uGojwXig=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,101,48,99,97,98,54,
                     57,45,57,99,53,99,45,52,51,56,55,45,57,54,99,56,45,48,
                     55,100,97,50,101,97,98,52,52,54,50>> =>
                       <<"±FAuAg6k3JEfgfowb7Wkpw47vDnAc64qWet8jN5US6j4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,51,98,52,51,49,54,56,45,
                     97,101,99,57,45,52,54,49,97,45,57,49,98,49,45,50,50,49,
                     50,49,102,100,101,48,97,48,99>> =>
                       <<"±xbQUuVvo20Ju9xN4cQOlWxnIg+1W9LHg0gc+xSS+S88=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,48,52,98,100,51,53,
                     45,97,49,56,50,45,52,102,54,56,45,57,49,54,101,45,49,53,
                     97,101,55,100,97,49,49,50,52,48>> =>
                       <<"±PHgPsPkrSfTIo/eRCssZcB/I/7JRG/BBxYYrAQebkL8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,101,54,99,55,53,98,101,
                     45,52,55,101,52,45,52,54,100,100,45,57,100,51,50,45,102,
                     57,100,56,100,49,57,97,98,102,57,102>> =>
                       <<"±2GATquqEmbM/VvygOXjZl4KX4ZdJNHhi5Zc5YB+KofU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,101,57,57,97,48,97,49,
                     45,55,49,52,102,45,52,50,102,49,45,56,57,51,100,45,55,
                     100,48,57,101,52,52,99,99,100,57,51>> =>
                       <<"±JtE63FrBsIq/xynIgZfj0VvM/TJzPxb+CBcb1oPZxyw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,50,52,52,99,51,49,45,
                     50,48,102,97,45,52,54,48,55,45,57,53,53,53,45,98,100,
                     102,56,55,51,56,50,100,48,98,51>> =>
                       <<"±A/o7331ZEIR89b8YQITTGg11D0Zwg7C2AfTXkZbZiWA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,57,54,55,56,99,54,99,45,
                     55,48,54,51,45,52,48,97,97,45,97,52,49,98,45,55,57,101,
                     56,56,101,48,98,101,49,49,101>> =>
                       <<"±AC559TRTEjKQ8Qjl6aZMxrUwlMonF98hxvSBezLQYFQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,54,100,54,52,52,53,
                     102,45,55,48,98,98,45,52,56,50,101,45,57,54,101,100,45,
                     52,99,52,56,57,54,48,99,100,48,99,57>> =>
                       <<"±AZSZUNgGiN403JO3lW7SKkIFJIEv9rRCd5iWI78SLAU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,56,56,52,99,48,97,100,45,
                     54,102,49,54,45,52,56,54,53,45,56,102,50,57,45,55,97,56,
                     101,53,100,100,57,49,99,101,52>> =>
                       <<"±b95nup1AzM59kao00afXkKytTKTx9kpu+l1X+AEaxXg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,50,57,51,97,98,100,48,45,
                     54,53,48,97,45,52,55,54,48,45,57,100,100,100,45,56,54,
                     50,100,53,98,49,97,99,49,101,49>> =>
                       <<"±ByUi19X1KNsaU4WumV8jt6HfJzSrzzOZL2nLHOV2ANQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,52,51,100,102,53,49,
                     45,53,55,54,51,45,52,51,50,51,45,56,54,102,98,45,97,50,
                     98,99,102,54,54,102,97,98,102,52>> =>
                       <<"±Qs1PQk9qsHanJRruKeosuFDuCHwzB9KF0QObJkRT0zU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,101,101,53,48,98,99,
                     45,98,51,52,48,45,52,51,56,100,45,98,53,99,48,45,51,56,
                     97,55,100,48,50,102,54,48,54,49>> =>
                       <<"±nzUGet/V0i1/XptVS5ZHukWcTPSmMHV3bWuqOuuraiE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,55,57,54,56,57,49,45,
                     101,101,52,57,45,52,98,102,52,45,97,54,99,54,45,48,55,
                     97,52,52,51,52,98,53,57,100,56>> =>
                       <<"±ilQJvg7FWYzSkHnYj+Gh9pKEK81rLh0fen+pFNy0RjA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,55,52,57,57,100,100,99,
                     45,56,48,48,54,45,52,54,52,53,45,97,53,53,99,45,52,49,
                     53,97,56,101,98,102,56,54,56,98>> =>
                       <<"±dUh8AjrgRf6Vyi3qDgOKdaDFLj+acgiXdVmcju2gmoU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,51,57,57,99,99,55,45,
                     57,54,99,54,45,52,48,49,101,45,56,98,55,98,45,53,55,97,
                     51,55,97,54,51,53,102,55,51>> =>
                       <<"±0I/otIqLJjX4jWwX8CA2vIrPxyWYep6ZCesgQFqVPdY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,48,54,53,100,53,48,
                     54,45,51,99,97,100,45,52,56,56,51,45,97,57,51,57,45,57,
                     55,53,57,100,100,53,51,53,49,100,102>> =>
                       <<"±oBgH9vqHS6IFqQnrgumwlGsT/fjxNg+XY2hcCD0gP2A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,54,97,53,55,57,48,51,45,
                     99,53,100,51,45,52,50,55,102,45,56,102,53,99,45,101,50,
                     57,57,100,97,99,55,48,97,48,54>> =>
                       <<"±HcRKNqdxHB91/H5uBtF1C/RUfUw+ovjF4f0e8fIsFYQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,54,52,51,57,53,48,53,45,
                     54,100,98,101,45,52,52,54,100,45,57,54,48,51,45,49,56,
                     55,99,57,53,101,100,49,54,53,57>> =>
                       <<"±pab2H88FPK8JiA1m8bm/SQWuNqUDCfwkcBQtInypSds=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,102,97,55,48,55,99,55,45,
                     48,49,53,98,45,52,49,50,54,45,57,54,50,51,45,51,54,98,
                     97,56,102,50,51,49,54,48,97>> =>
                       <<"±eXL4UPgT+r6xTBPvtDfHmMdEH7KCvE8RLI50hTWLMTE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,48,51,52,100,51,98,49,45,
                     101,51,48,56,45,52,97,97,98,45,98,98,57,51,45,52,55,98,
                     102,49,53,100,97,56,56,51,100>> =>
                       <<"±nlpkvq/SGUm0P5KwAy9TEcp4AuZYuRnOpHondrarDvY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,97,49,51,52,53,48,102,
                     45,51,56,54,56,45,52,56,50,49,45,56,101,53,54,45,48,49,
                     48,56,48,56,97,100,102,57,53,101>> =>
                       <<"±XBtTcDyXhJQMuI8bozXGuTXw/03UdXYJ/I7dPycGsTM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,50,99,101,48,102,50,102,
                     45,50,50,57,54,45,52,100,50,98,45,56,55,48,99,45,56,54,
                     99,55,57,102,99,101,57,54,54,97>> =>
                       <<"±GoPtjNUcFQ9KSq3o5OpRCFTZ7XsxYg9Lbp008lvcCVk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,50,100,100,97,98,51,54,
                     45,54,53,57,57,45,52,102,51,50,45,57,99,53,53,45,97,99,
                     54,98,49,99,100,52,55,49,51,99>> =>
                       <<"±roGvvnCFyh6HkA0cw5fmdIepbGxrZrSdfZ2AIvK6uis=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,54,101,48,48,57,48,
                     45,52,99,55,101,45,52,102,51,100,45,57,50,49,101,45,98,
                     56,52,102,48,98,50,99,55,101,49,54>> =>
                       <<"±eES/K9ggZMS++1HzfaF2sUCvKuGvJGLt2MFuhNdUkDI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,100,54,53,97,52,101,49,
                     45,53,52,97,53,45,52,97,56,55,45,57,48,57,52,45,101,52,
                     98,101,53,57,50,57,48,48,51,56>> =>
                       <<"±pC76wPuJANHpXaNoAc4AnB1O0kjFunb9Vxu18INXsvI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,56,50,99,97,56,101,57,45,
                     98,50,102,51,45,52,53,100,48,45,97,55,48,98,45,99,100,
                     52,101,99,57,56,55,97,52,51,57>> =>
                       <<"±BBT8smON7W9zLUbnNHp+sOH56und2bnV4BjkUa7TzQo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,100,55,102,101,53,57,52,
                     45,98,54,57,102,45,52,49,98,56,45,56,97,55,102,45,102,
                     55,57,48,50,101,54,100,53,52,101,97>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,57,50,57,49,97,48,54,45,
                     97,56,55,56,45,52,50,100,52,45,57,50,101,99,45,54,101,
                     57,57,52,100,98,53,98,50,53,55>> =>
                       <<"±nfTehj3K1mUEsjAWxECbBijh+u3mOI0i1XagZFW3igg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,98,49,53,102,101,
                     50,98,45,51,52,102,56,45,52,52,54,97,45,98,98,53,56,45,
                     100,53,48,101,52,99,57,49,53,52,48,100>> =>
                       <<"±S86Y1H1vWAHD1gb2f+Z5y2vLBm0z8TtS9g/1ZiOqSwQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,99,49,53,55,102,51,45,
                     55,102,53,101,45,52,49,98,52,45,56,53,54,97,45,97,52,49,
                     102,51,100,102,101,97,56,50,48>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,100,98,97,50,97,48,49,45,
                     101,54,98,49,45,52,52,52,100,45,98,57,52,49,45,55,54,50,
                     55,49,98,49,53,54,102,98,49>> =>
                       <<"±mwYj9f25PUDCLo18/rMxl3kiCUL/fOqGrPPXlCauBnU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,48,53,50,53,55,101,
                     102,45,49,102,54,53,45,52,101,49,97,45,56,53,53,101,45,
                     55,57,53,101,97,101,55,101,99,50,52,101>> =>
                       <<"±CMFhVxLRYaHkIRnCaV2ct7WofqKSNWlj4M6wrPR3oHU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,98,56,50,51,57,99,56,45,
                     52,48,48,48,45,52,100,98,56,45,56,54,99,56,45,102,97,55,
                     55,98,50,50,98,56,101,56,100>> =>
                       <<"±8kG3VXXDITmV92EG3OXRTE5pchQ7mhVpM0tXyAgs/Cw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,100,53,100,99,57,98,51,
                     45,98,53,49,55,45,52,51,56,99,45,98,53,53,102,45,102,53,
                     49,50,99,55,100,97,55,57,49,54>> =>
                       <<"±pYqKDvywcxZNwkZK7xjEpDUH/3ArJk3Lw1sfIz9tR0E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,100,51,52,50,48,99,
                     45,56,99,98,54,45,52,48,102,53,45,98,54,53,55,45,102,53,
                     55,50,97,49,51,56,101,57,54,98>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,100,57,55,102,56,53,57,
                     45,54,48,55,52,45,52,53,50,101,45,97,57,56,57,45,50,50,
                     56,51,48,55,49,99,48,57,100,100>> =>
                       <<"±8kG3VXXDITmV92EG3OXRTE5pchQ7mhVpM0tXyAgs/Cw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,51,56,55,98,98,99,45,
                     100,53,98,51,45,52,57,102,51,45,98,55,52,53,45,98,48,49,
                     48,54,55,97,102,52,100,56,97>> =>
                       <<"±30+D4am1R/nACd7ZEc7aC9CNMuwcaDBvI7mPQ545pZc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,53,48,53,51,52,54,56,45,
                     50,52,52,48,45,52,100,51,99,45,98,97,51,55,45,102,97,97,
                     54,54,102,97,102,99,48,100,102>> =>
                       <<"±6o5KNQsya4O+0YDS9lP6z2drX2Cpx7ttnGhmat6SQng=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,51,102,57,54,98,48,45,
                     101,54,99,97,45,52,57,98,48,45,56,53,49,100,45,57,55,49,
                     50,48,98,97,49,54,48,49,102>> =>
                       <<"±Vk8Tqk9gVGC4WScAnw64aY/bATbtGwyedmeXoqwSl+U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,99,48,48,53,101,102,53,
                     45,52,101,52,97,45,52,101,101,48,45,98,56,51,53,45,97,
                     97,55,48,98,55,49,100,53,100,51,98>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,55,101,100,100,53,101,
                     45,51,49,55,49,45,52,49,52,53,45,97,50,102,97,45,102,97,
                     52,97,102,102,56,101,56,49,100,98>> =>
                       <<"±MMxdMIOOAVOCo1F7vvIgLRw9duwkTSIpaoBT+/vi/y4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,51,55,54,52,101,49,45,
                     49,53,100,97,45,52,55,98,50,45,98,49,54,99,45,48,100,57,
                     54,100,56,51,50,49,98,97,53>> =>
                       <<"±xttMOUQ3/Lgtjvwjq3yoVDN/hegkL+9fLVyG3+5pwDw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,51,51,54,100,49,57,56,45,
                     101,102,56,57,45,52,53,102,49,45,56,57,51,100,45,100,54,
                     98,55,97,51,51,49,57,101,53,99>> =>
                       <<"±51FRHuAN/5ptZV8qgoSGbi2MjzWiaRTl4GBEnGVdUrM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,98,100,50,50,49,50,45,
                     51,56,54,48,45,52,101,55,48,45,97,97,52,57,45,99,57,101,
                     51,55,57,53,48,53,52,54,97>> =>
                       <<"±ZZ2Sh2W6Fc3JK55IE9/JWXtR9K1eV0lO5SDOw4OZ+DU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,101,102,52,54,49,51,51,
                     45,98,54,101,55,45,52,99,53,48,45,97,53,49,55,45,56,57,
                     50,52,48,55,97,100,57,100,53,100>> =>
                       <<"±B9//7db1Lk3GqlzIitL9r1i1Vkp/nD7LIZfnDLvdQow=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,51,101,51,57,56,100,
                     45,54,51,49,55,45,52,56,57,98,45,57,98,99,53,45,57,102,
                     101,102,57,54,51,55,99,50,100,54>> =>
                       <<"±U1s4kukNLIHWWEzg/w4Kvy/wTy2at9btXgGMBQInLzE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,100,102,100,55,49,48,100,
                     45,55,102,57,53,45,52,49,99,48,45,56,51,49,49,45,100,48,
                     54,54,98,52,49,50,48,102,53,55>> =>
                       <<"±vZkvCorge/9ItiQ/neqfxE2/2pwvhAY9+fO4y0LHxPU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,49,53,54,50,53,98,45,
                     101,56,101,53,45,52,50,50,98,45,57,55,52,99,45,50,54,52,
                     53,52,48,98,54,98,102,102,99>> =>
                       <<"±0/akr3VQkpnHvoPe4M9bKTwtHX2kcjR31YUcbFSHYdM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,48,102,53,101,99,51,57,
                     45,49,98,52,57,45,52,97,101,52,45,97,98,54,53,45,101,55,
                     54,54,56,51,97,57,57,49,97,50>> =>
                       <<"±qdUxCzEQX0tOwnD0+g0ieAMifTJp4C+PX2RwNqranaw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,102,53,49,50,53,49,51,45,
                     50,102,50,101,45,52,55,98,55,45,97,53,55,50,45,49,52,55,
                     53,54,99,101,56,102,98,54,56>> =>
                       <<"±HpF8DJsvHzn043bUIu+YOkNwILjKRXG3Q8hbWBxkQCI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,100,102,52,50,54,
                     55,97,45,54,50,102,102,45,52,51,50,52,45,56,98,97,55,45,
                     97,100,97,57,52,101,49,101,55,52,57,57>> =>
                       <<"±HdGvcYxlMyXEYPhRVnQ4J2FhcLAP3flJ2QUffu8DT8w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,50,100,49,101,48,100,
                     45,99,54,102,56,45,52,102,48,97,45,56,97,51,100,45,51,
                     54,98,102,57,98,101,56,55,52,50,56>> =>
                       <<"±kKgLls0L/FOtIDKt7Nqtp52qTW5hh9ZyVJOQVh+HNB8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,57,99,54,52,102,52,56,45,
                     101,51,100,98,45,52,56,55,50,45,56,100,57,99,45,97,49,
                     51,54,101,55,50,101,52,98,55,52>> =>
                       <<"±fPEScEdwvIB/IXPJEnsTZOBmZhzF1DVLbp/nI5jCdFk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,57,54,101,48,98,97,
                     45,57,97,57,50,45,52,56,101,99,45,98,97,56,52,45,48,102,
                     57,102,56,55,97,99,51,53,50,48>> =>
                       <<"±7y6SCszivfZ1f0OHOWpwKvwLXz842bQu4e5GiIhQrqE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,99,57,55,52,48,101,55,
                     45,50,49,56,50,45,52,102,100,51,45,98,56,100,49,45,57,
                     101,57,101,55,57,55,56,51,56,54,56>> =>
                       <<"±jUkGzJwukKnfstrUFrSkn8ymfS0Ug6cfVhqesMmwg5w=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,101,101,97,55,50,
                     54,52,45,52,100,56,102,45,52,100,52,100,45,97,102,54,99,
                     45,100,99,53,100,53,54,99,53,53,54,50,99>> =>
                       <<"±ij8Gt248tMdgSmH+r0GndhcnQpYJpI2fHKBkk+mKwFA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,49,53,101,49,54,102,97,
                     45,48,57,101,53,45,52,101,53,99,45,57,102,50,52,45,48,
                     51,49,98,99,100,56,101,97,101,57,53>> =>
                       <<"±VDuYB9F/YNYXGK+qrTI125fwsE+s5x5cjwKI3G36Rc0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,56,97,51,50,49,97,
                     97,45,52,99,49,97,45,52,100,100,50,45,56,53,51,55,45,53,
                     49,54,98,49,48,49,53,99,99,100,102>> =>
                       <<"±74m+2zL12uI86GjbrjlkDCfjmW6IA2RrjzdOKvfqneE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,48,52,57,48,56,57,45,
                     49,57,56,56,45,52,49,51,57,45,56,53,56,49,45,48,97,56,
                     52,48,51,51,101,55,50,52,51>> =>
                       <<"±uUBDbYDH53AO4H4bW03jy02eEQslh5iPfNY/Er1/LXg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,49,101,50,98,55,52,
                     48,45,100,54,56,54,45,52,101,57,54,45,97,99,54,50,45,98,
                     99,49,53,54,97,55,49,100,53,99,57>> =>
                       <<"±rClWWVfUuJPDJUnNk2cOBIPKGK2KxPeuxyFEm1DmQH0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,57,51,97,53,53,101,48,
                     45,54,56,52,49,45,52,100,54,57,45,98,98,52,49,45,48,49,
                     102,53,52,53,50,54,48,55,53,100>> =>
                       <<"±ARdoF13udCaqyLkRSq+uwE0duLrsUAFKqLDk6mSohjQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,50,51,98,57,102,102,51,
                     45,102,52,98,101,45,52,99,54,52,45,97,102,99,57,45,50,
                     53,55,99,51,56,100,49,102,56,48,97>> =>
                       <<"±g13mCv6guY+8tYF/zFIHHUvNyUCq38YUr5/AoMiuzzY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,102,100,52,99,99,101,
                     45,101,53,54,52,45,52,52,50,100,45,56,97,100,54,45,99,
                     54,53,54,53,52,57,49,97,53,49,98>> =>
                       <<"±UdhUw6gxU64veI8Ta3FLreu2OKNrww1fRWvi1izN44Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,100,51,57,54,55,100,48,
                     45,55,49,52,101,45,52,52,101,55,45,97,101,99,100,45,51,
                     97,49,55,55,51,50,49,52,51,48,52>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,55,53,51,101,51,101,50,
                     45,99,50,51,98,45,52,102,55,57,45,97,101,98,56,45,99,48,
                     54,48,97,98,48,48,52,56,52,97>> =>
                       <<"±AmQplDQbSVQu9PdUAyJ6jYupXxoWlu612evbsfIcLbM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,49,98,57,55,50,57,45,
                     97,97,101,101,45,52,57,56,100,45,98,57,57,49,45,55,98,
                     51,97,53,49,100,98,100,57,55,52>> =>
                       <<"±aSume48qHL1jHea0Lj/XIsaZe3+joFfbNSZjHXFSslw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,99,49,52,52,98,98,100,45,
                     51,48,49,50,45,52,98,100,99,45,57,49,99,54,45,97,100,51,
                     55,51,98,54,52,48,99,101,52>> =>
                       <<"±ryHXVS8yklFMG5O2EE8ssYb3ZxOTxMrFuyrhi4AwxIw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,100,49,100,102,57,54,49,
                     45,55,57,50,53,45,52,97,55,97,45,98,54,102,99,45,52,56,
                     52,99,56,55,99,52,56,48,99,53>> =>
                       <<"±p/aqGeqJtomA6E+pAvoV9Wp8kYNbPzjRZzdwhBS7B0Q=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,55,52,55,49,50,48,
                     101,45,99,99,48,52,45,52,48,55,102,45,57,100,98,102,45,
                     56,102,100,99,55,50,50,102,50,49,98,98>> =>
                       <<"±HlnvX8jH/4/mggf5Z/hXCeFjSsePgiq4l8ukkn8OZQ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,53,56,49,99,55,48,99,45,
                     49,49,102,102,45,52,50,52,54,45,57,54,50,102,45,101,50,
                     97,97,57,48,101,57,57,56,48,102>> =>
                       <<"±+wO9aHtE+3vgHjW5BHgDxLqjld1u6NC4q7HTH/fuwY8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,51,101,100,100,98,97,56,
                     45,55,56,50,57,45,52,98,99,56,45,97,55,56,53,45,98,56,
                     57,57,101,56,52,50,50,101,51,51>> =>
                       <<"±R4TJyRapnawu+7EGJ5i6ndyePXPSmGm2XWVzfuCCD3o=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,51,102,98,102,56,
                     52,55,45,49,50,99,54,45,52,97,48,99,45,97,53,51,50,45,
                     50,99,101,55,50,100,57,52,50,49,102,56>> =>
                       <<"±muz+3cBZQyjE/6Et3SORaEO+Ijbjk8azzfpBPG7ws10=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,55,57,56,97,53,99,54,45,
                     57,55,49,97,45,52,100,55,100,45,98,100,97,52,45,100,100,
                     52,48,100,98,55,49,57,57,99,102>> =>
                       <<"±CAQ8Nt+WIRBaLjs5eRHBAmlY7qcYrJNYwRJC6WDeCKE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,56,53,50,53,53,49,
                     100,45,56,99,99,97,45,52,57,102,53,45,98,99,98,100,45,
                     50,102,49,102,52,49,48,54,56,100,55,100>> =>
                       <<"±jvDAgT3q9QUqQ+8BxP8JajYF5XsQl6MyrJbY+kEpJE4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,98,49,54,100,50,55,50,45,
                     102,54,48,54,45,52,100,98,101,45,57,50,99,53,45,55,52,
                     100,100,50,48,53,48,50,56,99,100>> =>
                       <<"±upQn8aw+m3AXTRzOvLgdddS/KsqRX5Rxn8i0Jf7pJZ0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,49,55,50,102,52,100,53,
                     45,49,56,54,101,45,52,52,97,52,45,97,56,55,54,45,53,57,
                     101,101,48,98,56,50,101,55,56,49>> =>
                       <<"±1msQjPzz//WOYw9HS36BM9QpCs4RUThtYADRzrCipKM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,98,54,102,51,102,52,97,
                     45,101,52,102,100,45,52,97,98,50,45,97,55,49,50,45,52,
                     51,48,57,101,48,100,56,102,52,50,48>> =>
                       <<"±gcrSurn+GEwqd2/Kb9cjPTFzQfLfXTyGmwX07gGYjmc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,97,100,49,49,97,50,45,
                     54,51,54,49,45,52,49,51,57,45,56,50,49,52,45,55,54,53,
                     49,98,48,49,102,48,55,54,54>> =>
                       <<"±aMR81kUFksy9TbpD16NPnQINAcHwdUCZVHSe9CMq2FM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,50,100,98,50,51,49,48,45,
                     50,101,48,97,45,52,54,99,49,45,98,54,102,100,45,49,100,
                     49,99,100,51,97,54,48,51,97,54>> =>
                       <<"±xhcvGURjAQC5OQQntUcVbCX9v7i1xTSwZSU82qZ6NEM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,100,54,57,55,57,49,102,
                     45,55,51,101,98,45,52,54,98,49,45,56,54,57,100,45,52,48,
                     51,99,55,100,100,102,51,54,102,52>> =>
                       <<"±09avGWUBhizlbySGFhCoEOeql6PKdtPNg9sTe+n/Qhc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,50,55,52,53,99,50,45,
                     48,101,102,100,45,52,53,56,102,45,56,54,53,98,45,100,98,
                     57,54,55,99,49,99,55,56,53,55>> =>
                       <<"±TE/OYpc2+zeNFZ40Mvlu2TxlfdYWnNGnm7gLguQuJSQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,57,98,97,49,55,55,48,45,
                     51,102,55,57,45,52,52,97,100,45,97,53,97,51,45,100,97,
                     50,98,57,51,102,57,48,56,53,54>> =>
                       <<"±aTRrfKwDWdieB54ktGe45mrivxSvKCOLjCPh3M95FlA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,51,55,99,98,99,97,
                     100,45,55,98,102,52,45,52,102,101,55,45,98,54,57,97,45,
                     99,98,99,57,101,101,98,51,102,50,52,57>> =>
                       <<"±JtpuKVz4rid2WS4pImG1OH6RtUWpek/5bF/ZN6R6BeY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,50,57,57,49,101,102,55,
                     45,50,57,55,51,45,52,101,51,97,45,56,49,50,51,45,52,50,
                     50,98,98,52,97,48,50,56,53,98>> =>
                       <<"±ogO/ZRybZpKgJS70Cnov6D6Sihw/wfzBDaY2EhiZbsw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,98,56,99,101,100,49,97,
                     45,98,98,102,100,45,52,48,51,56,45,98,97,53,101,45,102,
                     97,98,50,48,57,97,101,50,53,101,101>> =>
                       <<"±YUeKBnDSryHMPApC+1kgS9iaWruJpB66wb/WNGviYiM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,99,49,56,98,52,99,57,45,
                     48,102,49,99,45,52,52,100,102,45,98,98,48,99,45,100,99,
                     98,98,57,99,98,48,102,50,99,51>> =>
                       <<"±2x0IvV2dZDmPPWuWLylkBYoqf8wk9tcpklgd62wtnnA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,52,48,48,53,100,49,
                     51,45,56,52,99,50,45,52,49,97,57,45,98,57,55,52,45,99,
                     99,54,102,102,56,98,51,56,101,50,48>> =>
                       <<"±WpM86RxFOtqE9mOuL8qzUUVU7frKFpr5vL7VqZIy7VY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,53,99,50,100,100,
                     51,56,45,52,54,54,101,45,52,102,57,54,45,98,49,50,55,45,
                     55,49,98,98,101,48,57,51,56,50,102,50>> =>
                       <<"±81ul9oyzo20GFArCbK4U1Jq2bqLzQStmXQPm12sGG50=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,97,55,100,53,99,56,50,45,
                     57,98,97,99,45,52,51,99,56,45,97,101,49,53,45,48,102,98,
                     51,50,51,54,98,101,57,51,52>> =>
                       <<"±9QjWsmF4IZirD/3W6qNAg3Y95F8hjONCyE/3pCcaKis=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,100,57,52,55,98,97,97,45,
                     52,51,98,49,45,52,49,54,53,45,56,101,102,101,45,101,57,
                     101,49,57,50,57,102,57,55,52,97>> =>
                       <<"±Um1Vixgv4242W6ukpygptb7rz7GOzn37aani0eWhDVI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,102,97,57,57,51,50,100,
                     45,53,51,102,50,45,52,51,57,51,45,97,50,55,97,45,52,52,
                     56,49,55,56,57,101,56,50,98,51>> =>
                       <<"±Mx8tCGCn2dYcdoOtKgZyRa5Jo+01LQX8vCLmYQz8V0A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,99,49,52,55,56,56,45,
                     99,56,101,55,45,52,100,51,53,45,98,53,52,48,45,100,49,
                     51,53,55,50,52,98,100,57,53,54>> =>
                       <<"±2bB936P5v/dlNFuDUuycQV+ZyUAwEyxufqGnOeK1Kt4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,99,52,50,50,99,52,45,
                     49,101,57,102,45,52,48,51,56,45,97,102,97,99,45,50,57,
                     98,100,56,56,97,50,50,101,99,56>> =>
                       <<"±YtOo5lRlodVLVp9GN5JXHTw1D6xVzMfSLqXEL6kmS20=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,50,55,51,52,97,55,101,45,
                     102,54,52,100,45,52,51,54,101,45,57,56,57,100,45,49,51,
                     50,48,53,53,55,100,55,56,56,56>> =>
                       <<"±A42RNqxMmHIJe0YBnBTyzU1b5DsfSsHlFyu7t3NHcVk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,51,55,55,57,50,49,55,45,
                     48,54,98,49,45,52,51,56,101,45,57,53,99,56,45,54,97,57,
                     54,100,57,57,53,56,57,54,98>> =>
                       <<"±O3fhykR0nrcmYos5TXgbu/L26r9h3x/MQTqv1Qw4A0s=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,54,100,102,55,97,100,56,
                     45,101,56,55,99,45,52,52,51,102,45,97,98,51,48,45,102,
                     98,101,99,56,49,102,98,53,53,99,53>> =>
                       <<"±Ae1PJPhYN1CVix2H9FulGamkJSkyF8hm26ht90SpKiE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,98,54,98,98,49,56,
                     56,45,53,52,100,55,45,52,50,100,53,45,57,99,57,49,45,
                     101,48,97,54,100,53,52,57,56,102,57,51>> =>
                       <<"±I6h+DPjEgxvqiw0Fgo+WWD90BOKZhYdcjHKhCMnF5y4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,55,48,54,48,51,52,57,45,
                     56,49,100,100,45,52,55,55,55,45,57,56,49,54,45,99,52,98,
                     50,102,102,101,52,97,99,51,57>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,101,50,102,54,55,50,
                     45,52,54,54,48,45,52,102,54,97,45,56,51,54,52,45,100,53,
                     56,100,101,50,98,97,50,57,54,101>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,100,56,102,49,52,54,
                     45,55,56,56,98,45,52,53,50,54,45,56,54,49,53,45,51,49,
                     98,54,97,98,99,97,100,98,53,97>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,55,50,52,52,97,97,53,45,
                     53,50,99,99,45,52,52,98,51,45,56,50,56,56,45,55,49,49,
                     100,99,55,100,101,99,53,54,55>> =>
                       <<"±YlCy5yd+zaKaHj8bWbgFgkbEgL4UzMKH01WEoBIrEQk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,54,48,101,57,56,100,54,
                     45,53,50,102,100,45,52,101,56,50,45,97,98,52,48,45,55,
                     52,48,97,55,54,99,51,53,97,55,99>> =>
                       <<"±0pqQnk9jsufelFNQBLkdL47d/subLalLknVnVr4V7lA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,56,48,54,52,57,51,45,
                     101,100,54,102,45,52,57,51,57,45,98,102,98,100,45,50,98,
                     98,57,53,101,57,99,98,52,55,55>> =>
                       <<"±CoWbUevtDavGQFMDB0lyl8qiPN5G1UvYtCq06uw2fTg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,51,54,98,55,51,102,55,45,
                     102,57,100,53,45,52,53,98,51,45,57,53,56,99,45,98,101,
                     50,97,99,102,98,49,100,98,99,54>> =>
                       <<"±x+T79GIvotpVC2G4MsjnIy4oPsmrRY8mp655tZKHjxo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,102,52,57,48,101,52,56,
                     45,52,50,51,100,45,52,55,97,54,45,56,98,101,100,45,49,
                     55,49,50,48,53,97,57,49,100,51,52>> =>
                       <<"±RTOSF9ELf3ZqNgeHeNNsFYmSl0kqokp6Q3Ym8QOZhvs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,101,56,50,50,57,52,
                     45,51,98,100,54,45,52,100,99,101,45,97,100,55,50,45,55,
                     49,57,97,54,98,99,48,102,102,101,52>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,101,52,101,57,49,
                     52,54,45,48,49,54,97,45,52,54,100,98,45,56,98,55,51,45,
                     48,57,101,99,52,99,98,98,52,57,54,49>> =>
                       <<"±MkMW4qEgujx8e8lsjsmee9xlgzR1BQe1Tygq/SAiMl8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,50,101,53,48,98,55,
                     50,45,100,51,52,102,45,52,50,97,56,45,97,101,50,57,45,
                     100,52,102,98,53,55,97,100,56,99,56,99>> =>
                       <<"±oBlctiaYrLXrCvTO0S+9P1dG+hR+TvAqYEZmPSrgM7E=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,53,98,98,50,49,98,
                     102,45,48,48,52,52,45,52,57,99,51,45,57,55,102,100,45,
                     50,50,57,100,54,50,52,57,55,100,97,98>> =>
                       <<"±gYLE1NuxTBTPyf9vlvCpSxzqjyJ+OdmvXUk53sPagPY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,97,55,53,52,57,48,55,45,
                     100,57,102,57,45,52,56,56,55,45,56,57,49,101,45,100,50,
                     51,48,50,50,101,50,55,98,55,54>> =>
                       <<"±sOZoCGupLDunZYi/B8bjNCsrMMbLFFB3Q76BD4rutb8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,50,102,102,51,102,48,54,
                     45,102,100,49,98,45,52,48,53,98,45,98,56,99,52,45,55,50,
                     55,51,56,102,98,102,98,97,48,51>> =>
                       <<"±AucngGUfwdn2nGupdJ1er2I7Pzy4DF8PvdpnfUllHqg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,100,48,54,97,53,50,
                     45,55,56,53,49,45,52,54,57,49,45,56,55,55,50,45,49,97,
                     54,51,100,102,102,49,54,97,48,50>> =>
                       <<"±4jEH/uNvalhaMmfoKFwFyzH+BL3M9stKCdIXprkw3nY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,51,56,56,97,101,98,54,45,
                     57,56,97,100,45,52,101,57,51,45,56,97,52,102,45,55,57,
                     53,99,97,52,55,97,52,102,49,102>> =>
                       <<"±jyidisRAOvkwH6CFGxaXPBJEViBcMKMZ0FmmdLJTe9g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,102,98,57,49,101,101,51,
                     45,50,56,100,49,45,52,50,101,53,45,57,50,57,57,45,55,53,
                     57,48,56,55,57,97,55,56,97,55>> =>
                       <<"±ZArvCiC3sTtldCJ975A22A98/hGrQJem66ALhuhTmnE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,101,97,54,100,102,56,99,
                     45,99,102,98,98,45,52,55,53,100,45,57,101,51,98,45,101,
                     48,49,49,49,52,50,102,48,48,100,97>> =>
                       <<"±51p8sA57b2QIV/FfPSaCE9MXN26IohLKdohXxAaLSnA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,54,53,55,97,56,57,56,45,
                     51,56,57,57,45,52,48,97,49,45,57,53,97,48,45,102,54,54,
                     99,54,51,49,55,54,57,99,97>> =>
                       <<"±TnoErsRRARmZP/al1Kz0accOnfAwFT49cMgPYjruvZ0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,54,57,50,99,97,52,53,45,
                     52,48,57,51,45,52,49,57,102,45,57,54,54,54,45,52,48,57,
                     52,51,56,100,102,100,51,52,98>> =>
                       <<"±o8U3aJsTGZpwDblZvjTPTLfzAe6nNn8rNOMTukfYnHU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,50,55,48,52,57,49,
                     55,45,48,50,54,49,45,52,99,98,51,45,57,53,57,56,45,98,
                     50,50,100,54,97,97,97,49,56,53,102>> =>
                       <<"±KmJsWxM5I+Ll2BID3ZOHixl190T/vQxOkvXMigGOouU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,52,100,55,98,49,97,53,
                     45,102,97,57,52,45,52,98,99,97,45,97,55,98,97,45,54,56,
                     101,54,98,99,52,49,50,55,49,55>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,48,97,54,101,98,50,
                     56,45,49,56,48,56,45,52,52,57,52,45,56,51,56,100,45,98,
                     49,98,99,49,99,57,98,101,100,53,98>> =>
                       <<"±xZthOH2BkbfBBOf8zwV27N+AjOHVmE7+68WV4ei5EEE=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,55,102,54,49,49,56,51,
                     100,45,48,97,56,53,45,52,97,97,100,45,98,52,53,53,45,97,
                     101,52,57,102,54,51,97,51,57,57,54>> =>
                       <<"±5mUlP/KJOsV7iC5TE3KPZbGERCh9z/sHbo6CzXaQC1Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,57,55,100,101,49,102,100,
                     45,97,101,99,52,45,52,97,98,52,45,56,52,101,49,45,101,
                     56,49,50,100,99,102,56,53,50,102,50>> =>
                       <<"±VeoJ5XFdCo2dlAGNRzvyOy1+Ywwq2x8aytO62nTG/QU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,98,55,99,98,56,53,56,45,
                     50,102,55,48,45,52,100,51,100,45,98,101,54,101,45,57,98,
                     53,100,56,101,100,48,56,101,54,48>> =>
                       <<"±2Z+gcWx4LQ1ZMIxn3RcYKwjdS1L63bkDiK7JzgNxVbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,102,57,56,57,49,56,57,45,
                     54,102,54,55,45,52,98,52,49,45,98,101,101,99,45,53,56,
                     52,50,53,97,55,49,51,51,101,48>> =>
                       <<"±WM6aMXdvGhuv6/mY7+H9IyeE2gTukN6xvUVLTLGkdaw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,56,52,100,97,56,57,57,
                     45,51,49,50,97,45,52,102,97,56,45,97,99,49,55,45,97,100,
                     102,101,101,102,97,100,53,54,52,48>> =>
                       <<"±alc0CJ5hOItksr7XErgAG+uzupEhK7hkkN7wGQjPVlA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,97,55,101,56,52,49,56,45,
                     49,55,97,101,45,52,57,99,52,45,97,101,102,102,45,98,54,
                     51,48,101,102,57,101,97,97,98,48>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,55,55,52,100,56,50,
                     97,45,101,102,57,101,45,52,98,55,50,45,57,52,53,52,45,
                     54,102,50,56,49,101,49,57,97,97,50,100>> =>
                       <<"±h6p1ZIBJ3eG+eVl3aRY4U08p2EJzPEAN6fTmM/glnoI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,50,54,52,101,54,55,
                     56,45,48,56,98,49,45,52,52,102,99,45,97,49,101,99,45,
                     100,51,57,53,56,49,100,101,51,54,52,97>> =>
                       <<"±es1VbYmKgAUoc0XjE3QNR6t9IuuXxccRRs4kEOeCxJ8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,102,50,54,99,56,54,50,45,
                     101,54,52,100,45,52,53,57,54,45,97,50,51,98,45,57,100,
                     57,101,102,56,53,102,102,49,101,48>> =>
                       <<"±ZLoNhQoCh+cNvzD7Wm+N/ptNker7UPBjYUOO/rJuyZI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,101,54,52,51,56,102,54,
                     45,55,100,53,99,45,52,48,56,51,45,98,51,102,50,45,99,48,
                     51,101,56,55,55,97,52,54,98,99>> =>
                       <<"±85HewIssM7pZ7BgL5lN9YIRKkUK8l785zWQS7eS1MVA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,100,50,98,56,98,
                     48,54,45,56,56,52,97,45,52,48,98,50,45,56,57,101,99,45,
                     56,54,49,101,52,55,101,52,97,97,55,50>> =>
                       <<"±vI6NdpZheC2N6JQLXryCd6FG2HPnIpYfqO7TXXncWvM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,50,49,50,101,101,54,102,
                     45,101,55,101,97,45,52,54,52,100,45,98,100,49,56,45,49,
                     48,56,48,49,53,56,102,97,49,50,51>> =>
                       <<"±YuQTtcRI7lpQjs7X9b1EWIVp5Dno9/T/+aiK2iBrdY4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,100,56,55,98,98,97,52,45,
                     55,102,48,102,45,52,102,99,53,45,56,56,102,51,45,49,49,
                     52,101,49,97,57,102,51,48,54,49>> =>
                       <<"±NQvABQxSV3u/mLNjral1XsP8SunGLvMowAT/94MPvsM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,53,97,101,97,48,48,101,
                     45,102,55,57,51,45,52,50,98,100,45,57,101,97,102,45,101,
                     53,97,99,52,48,55,54,54,102,52,55>> =>
                       <<"±XXcZqGgW277urOzSwTuamzYs9LAeXGD2RYQZP0OJCXw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,50,50,51,55,101,56,
                     45,102,99,48,98,45,52,51,53,50,45,56,55,101,97,45,50,48,
                     57,54,100,57,102,56,54,48,100,100>> =>
                       <<"±zl3W7nrW8eUV+MFxDuzqYjKC/jmbEEyMIvMcTCLkyG4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,53,50,98,50,57,55,97,45,
                     97,102,51,49,45,52,101,53,48,45,97,98,48,98,45,48,102,
                     56,53,50,49,50,102,100,101,99,99>> =>
                       <<"±rRUyqNvlnGjjBQoMwaCEnBo3Fbk5aSVqcbM/3ugMgaU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,57,100,51,102,49,53,
                     45,48,52,100,98,45,52,102,101,53,45,97,101,101,51,45,
                     101,101,48,98,53,98,101,57,49,51,97,53>> =>
                       <<"±eI+MRJqnXHmim+WYfRQTIBbx3u4M211UhumRvlWgqHo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,51,57,50,97,98,52,
                     54,45,99,52,56,57,45,52,55,100,99,45,97,52,52,102,45,52,
                     99,56,54,55,49,49,50,100,102,56,49>> =>
                       <<"±wECmhx9v/mC3SnUC+PRaO7TVfqRifmuCLVxqlnu/LLw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,54,49,99,49,97,100,45,
                     102,100,50,49,45,52,102,51,57,45,57,57,102,57,45,97,100,
                     100,53,56,55,102,102,49,100,97,99>> =>
                       <<"±QZFHH4rVbBEXkJbwHa+nbgUSbcyZJLaN5K9dSjHwUeI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,100,99,102,99,57,56,52,
                     45,102,98,101,53,45,52,99,53,99,45,57,101,55,51,45,100,
                     49,50,97,48,97,100,49,48,53,99,50>> =>
                       <<"±Sgo4Zpums0SCHXVuWHzEqU4Y/kfZOd7LckuIDRk4XjQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,48,54,50,97,98,49,56,45,
                     55,51,55,102,45,52,50,52,48,45,57,48,56,98,45,50,97,102,
                     97,55,55,97,52,51,51,52,100>> =>
                       <<"±uiH0MUXNKEjIKoC8FBLe21v4aoOmkD2C7jXomqx7Tv0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,100,100,100,99,51,
                     48,56,45,102,48,99,56,45,52,99,56,52,45,56,102,56,53,45,
                     51,49,50,101,51,53,99,102,49,97,56,52>> =>
                       <<"±CFnl2AE1HIi3jnNR7hRCZiHVJUb00ar9lnKSFAEALW4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,53,57,49,51,56,55,102,45,
                     54,48,97,55,45,52,51,51,55,45,97,97,102,102,45,54,101,
                     100,101,55,100,50,97,98,52,55,49>> =>
                       <<"±5iBZWbW87+f3oktUvrWfTtDexQheDJnpw4kWhkO7UtM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,57,52,99,98,97,99,97,45,
                     55,57,100,52,45,52,100,52,57,45,57,52,49,49,45,98,53,99,
                     57,55,50,50,52,100,48,55,101>> =>
                       <<"±GNlCOCOZkso92bYddMhbMz52xU7mzAnhvw9E3klv6Ns=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,54,48,51,97,54,100,55,45,
                     54,53,56,101,45,52,55,102,98,45,97,100,57,51,45,52,48,
                     57,100,52,55,48,48,51,54,101,56>> =>
                       <<"±+DOWxVcQAGHSuRAOlNf+P8k9Pt4sXcR64UqN+i5UOTA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,97,100,48,55,49,57,49,45,
                     57,101,57,101,45,52,97,57,55,45,56,53,49,101,45,98,53,
                     56,56,57,52,53,102,100,102,99,99>> =>
                       <<"±z2xNvvuOIoMG9NAdLCbaZV6n/4JMIGPkCJAGFBb43Vs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,98,102,98,97,101,98,
                     45,53,53,51,97,45,52,98,51,102,45,57,102,52,98,45,98,
                     101,54,55,52,55,57,55,55,98,53,102>> =>
                       <<"±5tgeWikmBQHFrC+vqHfyz+Q0EHqHigQCu04m/pN5BNk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,102,54,56,48,100,100,
                     45,50,48,48,100,45,52,98,48,57,45,98,98,57,50,45,48,51,
                     55,53,99,100,99,101,55,48,51,54>> =>
                       <<"±T6X8AoRuxCpgo2wUuVJJgIftVJMuqrxpKr5eBpZDYrY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,49,52,51,49,102,99,52,45,
                     49,51,50,53,45,52,54,97,54,45,98,50,101,49,45,54,55,97,
                     55,100,53,102,99,48,50,99,100>> =>
                       <<"±DRPMYc8S72vIcoGtyk44Q4fQyyeQ2wkIFm0pk4mTryM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,56,97,97,99,48,101,
                     45,56,98,52,99,45,52,99,52,52,45,98,51,52,49,45,56,102,
                     54,97,56,52,55,97,57,55,54,97>> =>
                       <<"±P470bXCJZGgYKc+ZphPk8D3/LD47buuC41vEnSVIl8g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,53,48,54,49,55,97,56,45,
                     51,53,55,99,45,52,53,101,55,45,56,102,101,52,45,54,98,
                     100,53,100,51,52,102,54,100,56,55>> =>
                       <<"±nUMHcfj4/ne3gbRMN6vX7UyYqtETJqAXY5ATTCdlf+c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,56,49,57,53,99,56,45,
                     54,54,53,98,45,52,98,50,49,45,98,101,55,99,45,50,99,56,
                     56,55,99,101,97,52,49,102,57>> =>
                       <<"±XYUTstG4e6vdBggvzMVnoRnP0PLx3DkcStAPt+SSt/w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,51,99,57,50,51,99,98,45,
                     99,99,53,53,45,52,48,98,48,45,56,97,98,49,45,56,50,49,
                     52,56,50,98,55,53,54,98,48>> =>
                       <<"±3EVD1l5uBNqEwBxnEoF4neNf7miXwXpydifdalJOe1k=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,102,53,54,50,52,
                     100,49,45,55,49,102,52,45,52,54,57,100,45,97,52,98,99,
                     45,101,49,51,101,57,48,98,54,49,57,50,52>> =>
                       <<"±ZdD6/okJcIRnM+It5IRBx8trczct06XgQYWm8ggsubc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,97,53,97,56,57,54,45,
                     102,55,100,100,45,52,50,101,98,45,56,99,100,54,45,48,
                     102,100,98,102,98,48,51,48,49,48,48>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,57,100,56,102,56,50,49,
                     45,51,56,51,51,45,52,57,98,101,45,57,51,51,101,45,56,51,
                     54,56,54,55,99,50,57,99,53,101>> =>
                       <<"±DLyS69q5uscpwsfFz2iogFHiV6R7gHbVLknUkdUQWYk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,99,56,50,50,57,51,53,45,
                     99,99,57,98,45,52,102,53,57,45,97,98,52,56,45,53,53,49,
                     98,102,51,51,98,102,56,100,48>> =>
                       <<"±LGQ7qNbvfVE2yH/zBIX29mRqbXRscewUZnGw+C5sTB8=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,52,51,50,54,102,
                     48,98,45,56,97,56,50,45,52,98,51,100,45,98,56,56,55,45,
                     48,54,49,48,98,102,49,54,50,97,100,53>> =>
                       <<"±cXRLaLKyleex19MqcuZ5JKtXJG1Xzv3z+uIBrd1yQ5c=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,57,50,54,102,51,57,50,
                     45,54,54,99,97,45,52,57,102,101,45,57,98,54,97,45,50,
                     100,97,54,51,51,48,48,55,100,57,57>> =>
                       <<"±0cC15MVggJ1/J6/YUlKTheNb8Lhc6Iqtkv4bsJVzdSU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,102,52,97,56,53,98,
                     51,45,102,57,50,48,45,52,52,57,51,45,56,100,48,49,45,50,
                     50,98,49,102,48,48,99,98,97,99,102>> =>
                       <<"±GqDnXeJ5nfmedwJe5DklyavmP77XsDCDMTQ0ZLG58yM=">>,
                   <<1,0,0,0,0,21,107,101,121,95,48>> =>
                       <<21,118,97,108,117,101>>,
                   <<1,0,0,0,0,161,98,109,116,95,50,101,54,98,100,102,100,98,
                     45,53,102,56,55,45,52,50,48,49,45,57,50,50,52,45,53,98,
                     57,97,102,48,52,57,49,99,51,98>> =>
                       <<"±bi+Ov+BmKBiidQo63F7aiQp/ElB3tWMVPQn6RuySAo0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,48,53,54,102,51,
                     100,51,45,54,52,51,97,45,52,99,101,100,45,98,101,49,50,
                     45,51,101,55,99,49,51,56,55,100,101,53,50>> =>
                       <<"±FXqnv5AKBVanSE9HQhr/9L67V9tyk8DiUblGYCOJC/A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,101,50,51,101,49,49,99,
                     45,100,51,98,50,45,52,100,56,98,45,57,101,51,100,45,99,
                     99,102,98,48,52,50,51,52,56,53,97>> =>
                       <<"±eMG5/tWB1JFSB+AbdUGzI9KpNjW68f9E5I/FI9zz/ig=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,54,57,100,102,51,99,97,
                     45,55,52,53,51,45,52,55,98,99,45,57,53,48,100,45,49,48,
                     99,54,51,56,56,54,57,101,99,56>> =>
                       <<"±R5qkINoN8JIkk1oTvHw0qWDdJyP+d0iio3aAoUOSn28=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,56,56,54,98,98,52,48,45,
                     48,48,50,52,45,52,53,53,102,45,56,99,56,57,45,51,101,
                     100,99,101,57,55,57,99,49,56,53>> =>
                       <<"±60pa5cOwdE5GmlmmknG5yBZX4xrnqhbzeFe46oXa8wQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,54,52,97,55,53,97,48,45,
                     55,53,97,100,45,52,50,101,99,45,97,56,48,57,45,54,55,99,
                     53,49,57,52,49,49,99,54,52>> =>
                       <<"±ndqaa62pVes7xnNxYEIWhgjEtOGKjycs6QsSv51fsYc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,101,100,102,102,99,50,55,
                     45,100,56,54,57,45,52,101,55,55,45,56,49,53,102,45,51,
                     102,54,100,97,52,101,100,53,50,54,99>> =>
                       <<"±HcO861clExmpZoyoYJUusx9UwLs58YukRfU3uyGJD6Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,54,98,49,100,49,57,45,
                     57,100,50,49,45,52,52,53,101,45,56,99,49,54,45,49,49,57,
                     57,49,51,102,101,102,98,48,56>> =>
                       <<"±vX1P3RPXkEZoKgar7gN1cgu++wjUENoCibLU5EhxEw8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,51,97,52,57,98,102,52,45,
                     97,100,49,50,45,52,56,54,48,45,97,57,102,53,45,51,97,55,
                     55,53,53,52,53,57,56,49,49>> =>
                       <<"±wzN2yJGbyhdo/8ZNZ+GdcooWINqS0cBC7t++dIVMtCw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,102,49,49,97,53,56,48,45,
                     101,49,56,49,45,52,99,99,52,45,98,52,101,51,45,52,56,98,
                     49,50,97,101,50,49,53,57,53>> =>
                       <<"±JJZYw49LwuvAjEtj0a+hKjCqXPi9/iGJz0YFjmjFOHw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,98,99,98,54,57,97,102,
                     57,45,53,48,49,100,45,52,55,48,101,45,98,56,53,52,45,
                     102,55,101,99,56,52,101,53,52,52,99,99>> =>
                       <<"±EIehLnwMdH/XPFQrlyvmvTXbsiLapKbzHEriFRhaJho=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,100,97,97,54,101,53,
                     45,51,48,99,101,45,52,101,97,57,45,98,48,99,51,45,97,99,
                     51,48,97,55,101,56,49,56,100,51>> =>
                       <<"±WHXMfIsEqdr+oE79SmXG2JOVsbmYoXPLts/Uu9PFNCY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,99,56,57,98,101,48,45,
                     57,100,97,98,45,52,99,97,48,45,97,53,53,100,45,51,52,48,
                     97,101,54,52,102,56,101,49,57>> =>
                       <<"±u1wEoavTeUdHBYlXJTo9qA+5Mvun2+szjpdmnLiCnQY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,53,51,51,52,100,99,97,45,
                     102,53,97,98,45,52,54,102,53,45,98,102,48,101,45,52,53,
                     102,55,54,55,100,57,99,101,54,102>> =>
                       <<"±Jx2IZBT76Z/7pEBnb79y+Fiwae/I5vlFjqRvFjmrF+0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,99,51,98,53,99,52,45,
                     52,98,97,97,45,52,50,56,102,45,97,55,98,49,45,52,49,98,
                     101,98,102,54,49,56,102,53,54>> =>
                       <<"±PghevbBLQzKh3OIKp0IOB1BwdhPyXQmtRFG054HjHKk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,56,55,98,57,99,48,45,
                     50,51,101,54,45,52,55,50,55,45,57,52,97,49,45,55,51,55,
                     99,55,99,50,50,55,98,56,102>> =>
                       <<"±taUGHSc21KMYxO1F30XRx5xeA73UJcVH+nyBZfaOInA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,97,97,102,101,53,
                     55,57,45,54,54,51,52,45,52,53,99,51,45,56,54,49,50,45,
                     101,57,99,102,49,97,102,54,102,50,49,101>> =>
                       <<"±YfOQeaNbhyRey57v3atJLWcfxXHV/ZDzGlesWC+RSEY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,98,49,57,98,99,53,52,45,
                     101,56,99,97,45,52,53,101,50,45,56,99,97,99,45,97,97,
                     101,54,57,51,56,55,101,102,99,48>> =>
                       <<"±b0G4LCqbWrKYAnzqjFM0FHjediHb4TqQz2iFSMY8AUk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,56,54,102,56,54,
                     100,55,45,48,97,53,50,45,52,98,100,49,45,56,102,49,51,
                     45,100,102,98,56,101,98,53,98,56,102,56,52>> =>
                       <<"±qsxAYucEuTIVPa7IIlg5LJJh+gdMQVAggjoTMyzi8XY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,101,55,98,97,57,54,45,
                     102,53,51,102,45,52,49,53,100,45,97,52,102,57,45,57,101,
                     102,51,57,99,51,56,97,101,101,52>> =>
                       <<"±FwQPR9md2Nt9NtsZcxHyl2VdDtpIqSORTexsroJBMdU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,54,102,49,50,50,51,
                     45,57,52,50,99,45,52,51,53,53,45,56,50,52,54,45,100,51,
                     54,99,52,55,57,97,97,55,102,56>> =>
                       <<"±hL1HJzH2gpTqcUSTkSNMHwmb2bsB+mb9Q/TYTESkmSo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,48,49,55,53,97,54,
                     49,45,52,54,97,99,45,52,53,100,57,45,98,50,50,57,45,57,
                     53,54,55,49,99,49,101,49,54,54,101>> =>
                       <<"±dcHe9CD1lhkumA6g6OHODSDjEgCZ0nbC/AG7+1l0umY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,49,54,53,49,98,57,100,45,
                     52,99,100,97,45,52,99,55,101,45,56,56,102,54,45,53,53,
                     56,97,53,102,48,98,101,102,97,50>> =>
                       <<"±GvV0IKWoBa40rXVFLz0kg5UN2wIKEFR/t/G3TnTiWr0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,97,53,52,49,56,54,
                     56,45,97,100,102,55,45,52,52,97,102,45,97,55,49,49,45,
                     97,51,49,51,99,100,55,97,50,101,101,102>> =>
                       <<"±1nZyTdRsEP8YlIpPTXVXGH6dr214wl3jOnodzDsFXi0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,52,56,48,51,98,49,57,45,
                     101,101,48,55,45,52,99,102,55,45,98,51,50,102,45,49,99,
                     56,51,98,98,102,99,97,53,50,101>> =>
                       <<"±i92iJeLYduSgMWAJvWM6bqgAGS5LSsfC5wlVu5jl5UY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,57,50,99,55,99,102,
                     51,45,98,99,51,50,45,52,57,52,48,45,97,101,98,54,45,51,
                     48,50,55,51,97,98,53,54,57,97,53>> =>
                       <<"±HvyqtFdauMPMGgCVf8IsRqgxG7HRbAqWvKg5cIf7feo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,55,98,54,51,99,97,45,
                     100,102,50,97,45,52,53,52,55,45,98,48,100,55,45,48,50,
                     99,102,102,56,51,51,54,98,49,97>> =>
                       <<"±/vDJn5UtVtslJPJjEV6FOPBCDG2YEPvVIYaF6kgg5f8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,52,55,49,97,52,54,55,45,
                     57,55,55,99,45,52,52,56,51,45,97,57,54,48,45,99,49,48,
                     51,55,51,97,56,51,50,57,52>> =>
                       <<"±GoPtjNUcFQ9KSq3o5OpRCFTZ7XsxYg9Lbp008lvcCVk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,51,54,102,53,50,54,45,
                     49,56,49,101,45,52,97,52,51,45,57,51,49,101,45,102,52,
                     99,100,101,48,55,100,102,101,48,98>> =>
                       <<"±8JZpXDE6xG64zAFqVUku4acCrhoHAR4hhb87c3E6xZE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,102,54,99,100,98,100,102,
                     45,48,100,53,48,45,52,50,100,48,45,98,98,49,53,45,53,51,
                     100,102,100,102,49,98,48,51,100,49>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,54,102,100,57,55,102,
                     45,51,52,57,50,45,52,49,48,50,45,56,51,56,52,45,99,52,
                     53,101,102,53,102,98,99,48,55,48>> =>
                       <<"±27qzRMlUzGL59cN0uL0bT3ipIkE2ZQBseffuNi3iVPk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,98,53,56,98,98,102,102,
                     45,102,50,50,99,45,52,52,51,51,45,97,55,49,97,45,55,99,
                     57,53,53,98,98,56,102,49,52,55>> =>
                       <<"±2ecUB/HJXsFvHeQlUVHfye/W0zeeFajfu+9N7Pu5eAY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,54,57,48,101,49,50,102,
                     45,100,53,97,53,45,52,102,55,48,45,56,54,100,50,45,49,
                     97,52,100,49,101,56,48,51,52,54,50>> =>
                       <<"±V6bVLbMsU2+Ovrc/+d+ltWX+3XCB3184k51lcuccxs0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,56,101,53,97,56,54,45,
                     54,51,57,50,45,52,99,48,50,45,56,56,98,98,45,56,100,56,
                     52,54,48,54,52,54,49,53,53>> =>
                       <<"±jdk3WBo6tcMtj52CGZYXZZCXGA5oFDuZtTEcIxOC05Q=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,49,48,52,52,102,98,49,45,
                     54,54,53,50,45,52,49,55,50,45,98,56,97,50,45,56,97,57,
                     54,55,56,100,52,55,53,54,102>> =>
                       <<"±i7YVwQf+Qj28ZV9M2AVOS8MepIThNyfNxVIw+uhNoqk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,48,98,57,53,48,57,45,
                     54,102,57,97,45,52,53,56,101,45,57,102,98,50,45,54,102,
                     51,50,102,52,99,57,100,49,49,101>> =>
                       <<"±/PoEOes76DTk2IlW11kc4A+sgT4KJIWQhxXGoMDLj24=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,98,97,48,55,49,101,45,
                     100,55,50,53,45,52,56,99,49,45,98,100,97,53,45,54,101,
                     97,48,48,50,99,51,100,51,51,55>> =>
                       <<"±f0xLRtg/PQz/w++6xcpLrxzu2NgzTAkmKy3o5d43JX0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,52,52,102,97,51,48,50,45,
                     57,53,51,53,45,52,56,53,100,45,56,102,53,100,45,101,57,
                     49,50,57,50,54,49,54,50,101,54>> =>
                       <<"±xcxI+r9ZU9pW+BqrtmbGJU+RZfAzLG03mZY5wFggXj8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,57,101,52,49,57,98,45,
                     100,50,54,55,45,52,102,53,97,45,97,57,100,99,45,52,97,
                     99,98,98,50,49,101,99,100,57,56>> =>
                       <<"±8RK6iYPiBje4H73Y2a3Eg8sfrAXv+Ek6E2UfZRF2FE8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,98,54,101,51,50,53,97,45,
                     101,102,52,100,45,52,97,98,99,45,97,57,48,51,45,55,98,
                     48,97,97,51,48,49,57,52,99,51>> =>
                       <<"±rE7b5dLzrbyeuX3ymkM4LO1YDsdVADBN/F/bkR0Xh5U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,101,57,100,56,57,53,57,
                     45,98,56,99,49,45,52,98,56,50,45,97,97,97,48,45,50,49,
                     57,101,50,53,53,50,51,51,102,101>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,51,98,102,100,102,49,55,
                     45,54,102,51,56,45,52,97,56,99,45,56,100,101,54,45,52,
                     56,97,56,55,53,56,53,57,55,99,57>> =>
                       <<"±m144eMN/JefKBIhSzWAw0Q+7FoheY5btXPpDIrNfULQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,57,52,101,57,102,55,
                     45,98,98,101,50,45,52,48,50,98,45,98,102,56,51,45,98,53,
                     48,98,100,100,49,51,100,56,57,101>> =>
                       <<"±57N6eRrQ6PyORdurMNoUCgynEFMzm1MBP9MIMysx5xw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,48,52,56,54,57,57,45,
                     51,101,50,54,45,52,102,97,48,45,97,53,102,97,45,100,57,
                     51,97,99,100,51,100,98,97,50,57>> =>
                       <<"±NUojmo6k2qcDk9nA17PJ1Sk7Uaa+BQop/xh4220yuIM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,57,48,54,97,52,55,56,45,
                     48,54,97,53,45,52,101,100,53,45,56,56,98,56,45,98,56,53,
                     53,97,50,52,53,50,50,100,97>> =>
                       <<"±G6vUYnOcX+cxWUYkvXMIHZhDS27CpJSXKja4iQy24n4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,55,49,52,98,102,97,
                     48,45,52,57,100,55,45,52,98,52,57,45,97,98,102,53,45,55,
                     100,52,99,50,49,54,102,99,101,50,52>> =>
                       <<"±f//T8xGsVJeW6gWZJQtytsbF4h96qPrCFdy1dKg6UKI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,56,56,102,52,55,99,49,45,
                     100,98,48,49,45,52,97,55,100,45,98,55,57,53,45,97,51,52,
                     51,50,102,100,98,97,99,53,56>> =>
                       <<"±FJfZZH/09W8o0KzSXcy2IzuiCHzutIgUrW6+kwwk+iQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,56,49,52,56,56,54,
                     52,45,98,55,97,53,45,52,48,50,48,45,98,53,100,50,45,50,
                     102,53,99,55,57,51,100,51,51,52,50>> =>
                       <<"±aBl1Kz3jtfWRXuMsStTFdIKVRRWfX7Wpk3PRlPQvDxI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,98,99,102,50,49,56,97,
                     45,97,97,97,98,45,52,99,97,57,45,98,53,48,100,45,56,98,
                     97,102,98,51,57,57,53,55,56,48>> =>
                       <<"±UGXs93ZjrJL40yRGzNn/cFGv23wBsWcxQVpH9lifiQQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,48,54,48,97,48,97,100,45,
                     56,57,51,54,45,52,98,50,55,45,97,100,52,50,45,55,101,
                     102,57,52,56,98,101,55,51,49,102>> =>
                       <<"±qZSO5h2R5oYjEjqPFCEEpDqYsf+1ji/i8YSYPlmTeyY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,56,56,48,100,100,101,53,
                     45,50,52,99,52,45,52,56,100,55,45,97,52,54,97,45,50,52,
                     98,50,98,55,52,101,53,56,102,54>> =>
                       <<"±m59//wABIqn/n1SD/3Fzla0y+N2o+YqkTdqA5CHB8tA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,51,51,52,50,50,52,99,45,
                     54,51,101,97,45,52,56,97,49,45,98,52,98,99,45,48,49,100,
                     55,51,54,57,54,52,55,49,48>> =>
                       <<"±PgSWA8h67eqzNuvlRfyK1tRhXvKs7akGbAKsY89h3V0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,97,100,54,100,53,102,56,
                     45,55,54,53,56,45,52,102,55,101,45,97,97,99,100,45,98,
                     55,102,50,98,51,51,102,52,101,55,50>> =>
                       <<"±wNP6Zsq6/QPanuNkBms3WW2wPQLv9y0CIkVkdzLOYVg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,49,57,52,57,53,51,100,45,
                     50,48,100,50,45,52,54,56,102,45,97,55,97,99,45,101,101,
                     54,99,97,48,48,53,52,99,48,56>> =>
                       <<"±pab2H88FPK8JiA1m8bm/SQWuNqUDCfwkcBQtInypSds=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,101,56,54,51,51,97,45,
                     98,98,49,53,45,52,55,102,54,45,97,54,57,53,45,48,48,54,
                     54,50,49,49,102,57,100,101,57>> =>
                       <<"±Avbx2kGPnXl9gqXdXIeZcJ4dzxeDAPg21wJQaFqBG6I=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,56,52,49,50,99,57,
                     48,45,54,100,98,102,45,52,53,52,52,45,56,49,97,49,45,50,
                     54,98,99,99,57,99,51,51,54,55,48>> =>
                       <<"±wAtMdM4VEnELvIPNJnu+FDYtow2GS+MRefvSNV/J+Xs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,48,54,99,50,53,102,102,
                     45,55,54,50,57,45,52,52,99,97,45,97,54,52,51,45,101,51,
                     51,55,48,51,53,99,53,52,53,97>> =>
                       <<"±YlHU2Eke2SKC/GGnINB3Hz/CC583xzNDRmckTa0H9DI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,101,97,50,101,51,
                     97,56,45,98,49,56,56,45,52,97,99,52,45,97,102,56,101,45,
                     49,57,55,98,57,100,54,49,50,49,99,99>> =>
                       <<"±Ge7Y/xceIyHjbF8grBtCfCyoAmg9ydeBlhoQpPygLng=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,48,101,51,48,54,48,102,
                     45,99,99,100,54,45,52,97,100,54,45,98,53,53,102,45,50,
                     57,102,53,52,102,98,54,98,55,50,50>> =>
                       <<"±o67KciN1bSncQ/mr2XDAA5CcvaapnNeoawAGiByoykU=">>, 
                   <<1,0,0,0,0,161,98,109,116,95,48,97,48,48,98,101,52,102,
                     45,57,50,99,98,45,52,55,97,49,45,56,98,54,53,45,102,49,
                     98,53,51,98,97,53,55,97,54,57>> =>
                       <<"±VRnZSxoPs4yFHogClBJcLQkkGf4brP1OO/lvkIwqCz0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,54,100,49,51,56,56,99,45,
                     100,53,50,54,45,52,51,48,54,45,57,51,56,99,45,54,52,99,
                     51,48,57,51,56,50,50,97,55>> =>
                       <<"±SH4/ut1KnVxV6T2bMPdgCA0D1joKtudVpJYXVpYOpsM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,57,55,99,55,54,48,101,45,
                     101,49,102,53,45,52,48,98,52,45,98,56,102,57,45,51,56,
                     98,57,99,51,55,98,56,49,102,57>> =>
                       <<"±U/5uLJ8orYAAITFixmK7vmIvPT6rauIFoGlCfALKo8w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,52,49,54,101,99,50,102,
                     45,50,53,48,102,45,52,49,49,48,45,97,57,54,98,45,99,48,
                     51,98,101,54,49,49,52,98,55,56>> =>
                       <<"±pZ0Yvo7L9+kSL6vK4WWAl1wxHM/vKHjRuFZJSvnxqyI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,53,52,101,99,97,98,57,45,
                     48,102,51,55,45,52,99,97,48,45,56,101,99,101,45,51,51,
                     48,51,102,54,98,55,55,57,101,56>> =>
                       <<"±QEkwTFFnxO1wQ77VnZeB3dYHInDA9qbSVdoidn8SqCQ=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,54,99,102,100,48,
                     99,54,45,100,57,101,99,45,52,100,52,57,45,57,101,50,102,
                     45,101,50,99,53,57,97,48,55,97,55,48,50>> =>
                       <<"±ss+a97wnbRLDk+zrxEsR6dyzuM4xvuRAzxuls7PT5UI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,53,99,57,51,57,51, 
                     97,45,57,55,49,56,45,52,56,101,97,45,56,56,97,53,45,50,
                     54,98,100,52,102,101,101,50,55,101,55>> =>
                       <<"±+vwiZa9ld0p9NlIIF75eKDOROv4KAiSVHe3aeUWoBZ8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,55,53,97,53,52,56,51,45,
                     55,100,97,50,45,52,55,101,98,45,97,98,98,57,45,99,101,
                     49,101,50,55,52,55,55,54,48,99>> =>
                       <<"±bXydY/brZeHm9/poFg9vdQPnY0Yu5MMVcpLx2eah3T4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,100,99,57,102,55,54,
                     102,50,45,53,55,100,48,45,52,54,101,100,45,98,56,98,98,
                     45,99,55,53,52,53,100,97,57,55,49,55,100>> =>
                       <<"±8O92E4EH1zfiEFUm6xk1H3gn82IrCcW8aL477R2qO4o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,97,51,100,99,53,101,102,
                     45,49,97,98,55,45,52,54,53,52,45,56,53,57,100,45,99,99,
                     54,49,53,102,55,55,99,51,50,101>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,101,55,100,53,52,48,97,
                     45,56,102,101,52,45,52,55,97,53,45,57,56,99,101,45,101,
                     55,102,102,56,101,54,52,51,50,51,100>> =>
                       <<"±2PcH+sEiKLuhASsW2a6blccSaDWToOdi9hlCCzzgcPk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,102,100,101,101,101,
                     55,45,50,52,50,54,45,52,97,51,53,45,98,54,48,51,45,48,
                     57,99,50,51,98,57,57,97,49,50,100>> =>
                       <<"±zqo5iNmFXrVt3nevriJFBdjjfbI0HH3u7fB3roD2jWo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,55,99,53,55,100,56,45,
                     49,51,51,100,45,52,98,56,54,45,56,49,102,50,45,101,99,
                     50,51,48,52,98,97,57,49,51,101>> =>
                       <<"±rU9FvZq+XCt4h5qpUkMxDWjEVtXUdpdAchNNwJBBtLI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,51,99,57,102,101,54,97,
                     45,49,48,48,100,45,52,100,52,57,45,98,97,52,50,45,98,53,
                     48,53,97,55,52,97,52,57,100,97>> =>
                       <<"±NtYA43dFNs/+XBCJJv8/+nQbpNp1Dnd0SGibxRw1JTU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,57,54,97,98,50,100,49,45,
                     48,52,50,99,45,52,53,54,51,45,97,48,102,99,45,99,49,54,
                     50,98,99,53,54,101,48,101,99>> =>
                       <<"±+zV2q3x8y15eM7rXOnFvOC0fsNN1usIq4IhAdUW7X5A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,48,55,48,102,51,56,54,
                     45,57,55,98,97,45,52,100,52,102,45,57,56,55,55,45,101,
                     97,100,57,55,48,56,98,102,50,102,98>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,99,53,57,99,97,56,100,45,
                     50,52,53,97,45,52,53,54,99,45,97,50,98,49,45,97,56,54,
                     48,49,98,98,102,54,48,99,100>> =>
                       <<"±zJQ9mC5JLdB7mXZ3Sn3UlCjUmGg0Dangmbt7/s14T98=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,101,51,101,56,50,101,
                     45,53,57,52,57,45,52,56,53,99,45,57,52,53,52,45,54,101,
                     53,56,48,98,100,99,56,50,49,98>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,54,53,101,54,48,98,98,
                     45,50,57,49,52,45,52,48,53,102,45,98,97,97,50,45,102,
                     100,101,50,102,52,97,55,102,51,53,48>> =>
                       <<"±I+plpHI+tuwJaeeKRqZEIWdKXpWkVaX1rmIX7Q+8coM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,52,100,48,53,49,102,53,
                     45,54,98,57,100,45,52,98,98,50,45,98,99,52,99,45,48,52,
                     48,53,102,49,48,52,99,52,55,56>> =>
                       <<"±K3lJfLzhgUTGfRuF5cqaJ7a2ZmIgKWbVdA/Q/xfTpgo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,54,101,53,100,55,50,53,
                     45,99,48,49,56,45,52,102,48,52,45,98,53,53,53,45,52,57,
                     98,56,102,100,48,48,54,56,54,99>> =>
                       <<"±eWKJQ/IEpEk2iGp7femppiURKc0ENUTaDlSA5qu0DkI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,99,100,52,101,54,100,56,
                     45,97,49,98,97,45,52,57,98,53,45,98,49,48,49,45,53,98,
                     53,98,99,49,57,102,53,51,52,101>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,101,51,54,49,53,98,48,45,
                     97,51,51,55,45,52,56,102,54,45,97,52,50,99,45,56,97,50,
                     97,48,49,50,48,100,97,48,99>> =>
                       <<"±OyyIIBQhJ2/ncguYadrSSd9AEYrj/dBScgucmiXTLzk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,99,54,51,53,50,98,98,45,
                     48,98,101,48,45,52,49,53,52,45,97,49,48,48,45,56,100,56,
                     50,51,97,50,53,100,99,102,56>> =>
                       <<"±1chSFFRZmIsOyUL3UrMlGMZPaSTkIeODm7165TIQrZQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,48,101,56,48,57,54,45,
                     100,57,51,100,45,52,54,52,52,45,98,98,101,57,45,55,57,
                     56,48,97,99,48,98,57,55,98,99>> =>
                       <<"±MpJtXWHN0XPF6BT7ihPOXYPZeGoNhuyWRvaYecyCKoo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,98,56,48,98,54,51,45,
                     51,98,97,97,45,52,102,48,98,45,56,50,57,51,45,102,53,50,
                     55,100,51,51,57,56,101,99,51>> =>
                       <<"±BxFn4h1kAbU3SFa/uglyUN9uWRJDj7xfLvjX7O80QTY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,56,98,98,99,51,98,45,
                     99,49,99,54,45,52,50,53,98,45,97,49,57,101,45,97,48,98,
                     48,51,51,100,51,56,101,102,48>> =>
                       <<"±BwvWH0V8SZ/sR7BUJipuYCUr4REL0sSJ0UizmsWnc/M=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,102,100,51,50,49,57,
                     45,51,99,98,102,45,52,101,53,50,45,98,97,102,52,45,100,
                     55,100,50,99,49,57,53,98,100,52,50>> =>
                       <<"±0Y+Mva1aWeEAU7d2Gs76CvL1LaKeZQGY3WiYtpQFZ80=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,102,100,98,101,98,101,56,
                     45,55,102,100,55,45,52,57,99,97,45,97,50,52,100,45,50,
                     101,99,56,101,57,50,48,48,49,53,100>> =>
                       <<"±0ymT8Ad2g5F1NFFs2CZqmWrAE2cy8T2LmsiAazE6yUw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,50,98,49,99,100,52,49,45,
                     49,53,51,50,45,52,56,56,97,45,56,55,57,100,45,101,53,
                     100,54,98,102,97,98,98,97,100,99>> =>
                       <<"±aAeO8u65PPgoAORyWh99vsWgXKB/cWn8G9xBR4pFPWM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,53,55,98,101,52,102,56,
                     45,50,102,55,52,45,52,97,51,97,45,56,99,57,55,45,98,51,
                     101,98,52,52,101,56,48,56,98,99>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,51,99,57,102,52,48,55,
                     45,101,101,51,101,45,52,101,52,97,45,56,56,56,51,45,102,
                     57,101,98,102,100,55,54,54,50,102,53>> =>
                       <<"±orj8gY1iB939iq+wia7T5MlhAgEOft3MSFG4GIwEgx4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,52,56,53,97,53,98,102,45,
                     101,53,99,48,45,52,52,100,98,45,56,99,49,54,45,100,53,
                     102,97,56,56,57,53,102,52,48,57>> =>
                       <<"±W4WHMA5mL9WUE9mgc1RmDAr81ZZXO2CvqFc/qYmxSVc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,55,57,98,102,102,53,50,
                     45,50,49,54,50,45,52,101,57,99,45,57,48,97,100,45,98,99,
                     52,57,50,57,97,50,55,100,52,56>> =>
                       <<"±9qX8BTr3uyRQ1QCWpFZW/2WqTbhl9rBI5PZb96Ynd6Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,49,55,53,48,98,53,100,45,
                     101,102,100,50,45,52,52,98,97,45,56,54,50,51,45,52,102,
                     48,49,97,57,101,55,55,100,54,100>> =>
                       <<"±qYjUHbqb8ngYvFTIp0DBD5oAYZ4U21P27O37r5WVDLU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,97,56,48,100,48,48,99,
                     45,99,100,55,56,45,52,57,100,53,45,97,102,100,98,45,50,
                     51,52,54,55,98,102,48,54,98,51,53>> =>
                       <<"±FcyOnRcNO/LK1MRAcKyv0E7nTdLHNK/QhVOqJkPcK6Y=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,49,57,48,49,102,57,
                     52,45,99,52,49,101,45,52,100,52,55,45,97,98,97,99,45,48,
                     48,56,99,55,101,52,48,54,99,50,100>> =>
                       <<"±86dKi/43ouQU0AOZi16jUTx6J1H1qO5JagPkD63S0fM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,57,98,57,102,98,54,102,
                     45,49,50,55,54,45,52,57,51,51,45,56,100,100,99,45,48,50,
                     98,100,99,99,53,50,49,52,100,52>> =>
                       <<"±RA3V3Z2zUc1knfwx3VmSYzLi8xh3tnB+osn+NQF4koA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,101,55,50,100,50,
                     51,57,45,100,52,51,53,45,52,57,99,56,45,57,54,50,49,45,
                     99,52,50,49,51,100,49,98,52,50,48,48>> =>
                       <<"±ayRU7f0rRiQxMAzfC36+u+CtDaxNnOV2daUPlZaB5nY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,57,54,52,102,100,54,
                     45,101,49,49,49,45,52,102,50,53,45,98,101,98,49,45,51,
                     51,102,54,49,98,98,98,101,51,51,49>> =>
                       <<"±3SAcEAfxYDW/yiMg4Yzv6Mh0SJndTR8ny3TuPF5CSSM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,97,48,50,50,57,50,45,
                     101,99,54,56,45,52,98,57,102,45,57,52,99,56,45,48,98,55,
                     99,54,51,102,53,48,49,50,101>> =>
                       <<"±9fzAeNJlvZ7HYMdHQHg+l82mIttHkNKZXeLCch5gMpo=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,48,100,98,55,56,57,
                     56,45,56,102,56,56,45,52,55,56,56,45,56,56,50,57,45,102,
                     55,50,56,56,55,102,100,99,102,48,100>> =>
                       <<"±7+4qlHipry2U1OtAsMalu5iXL1BciU4fd330ou4dJUk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,51,101,55,50,52,101,56,
                     45,52,57,51,55,45,52,101,49,50,45,98,52,52,56,45,50,55,
                     99,101,52,98,54,52,97,101,57,99>> =>
                       <<"±Ya++WS1CBmSfY0irLaMxkxvoldv8TbDGdP3BClzl9o0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,100,48,56,98,56,53,51,45,
                     51,57,98,52,45,52,56,56,48,45,98,98,98,48,45,56,98,102,
                     51,102,99,101,97,55,57,52,50>> =>
                       <<"±bjOpa+YkVQ6feFqcGPRv/vuuR08RFivny7RVt5iNlxA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,49,53,102,54,102,56,
                     45,50,53,100,52,45,52,54,99,102,45,56,48,56,50,45,57,52,
                     57,50,54,56,49,54,51,50,55,98>> =>
                       <<"±nXOgiDHNBryoIeCAfoS9yDS7gxBNLNCWge3ePgjLEjg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,48,102,98,97,51,57,53,45,
                     52,100,56,100,45,52,101,101,99,45,57,53,54,53,45,98,48, 
                     51,99,100,52,48,97,102,98,100,51>> =>
                       <<"±FMcPbmm3JiTfDv/pspnZObAUHV78w+JiWaPD/0LieZM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,102,57,98,97,97,49,45,
                     50,48,57,51,45,52,52,99,98,45,57,57,49,102,45,57,100,
                     102,57,56,101,53,100,52,99,56,51>> =>
                       <<"±42sqRJDf4MjWUDhrWoa42RoOtXAbcsU+6fz9N85WNRo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,100,52,55,101,51,57,100,
                     45,57,98,98,49,45,52,55,100,101,45,97,49,97,98,45,100,
                     102,97,55,55,99,99,51,56,98,51,48>> =>
                       <<"±DNBhy34DVOItU22DmYiE5wX15QCkXREIBGbNqkHg230=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,102,52,55,97,54,50,45,
                     53,97,53,50,45,52,56,52,49,45,97,97,49,99,45,53,98,102,
                     97,50,56,57,102,51,57,55,54>> =>
                       <<"±Xj6J98oq2M4otA0/MRS23GcuEDb2YLhyB6jezzAkP2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,49,57,48,99,56,98,98,45,
                     99,100,54,50,45,52,49,100,53,45,97,49,51,48,45,49,51,
                     100,52,48,97,98,101,50,51,53,56>> =>
                       <<"±Et4UQimf9/c8hF3Jc1mYo23QZ81N5oeLvpytzcdcfW0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,49,56,53,53,99,52,45,
                     100,98,57,56,45,52,101,51,102,45,98,99,100,48,45,48,49,
                     51,101,50,101,100,102,56,100,48,55>> =>
                       <<"±77b/K99i4uY6uMiyubjTslAOIpMVQBPAoZX4LNDIBnE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,98,52,51,101,97,57,54,45,
                     98,52,102,49,45,52,48,102,100,45,98,49,54,98,45,98,98,
                     100,51,50,98,50,53,100,48,57,54>> =>
                       <<"±0Huk/zzjW5oF6Fp2IJ/lmfneze0Qp5N61jw0wZeehqM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,48,48,98,56,56,53,55,45,
                     53,50,53,98,45,52,48,57,98,45,56,49,55,51,45,97,102,51,
                     100,48,57,53,97,97,100,100,102>> =>
                       <<"±Ql2qn6wNXkizAep8zLIO1ucwAmN28ci7nHzicLSVYrY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,101,100,55,97,99,
                     53,48,45,49,48,55,102,45,52,100,55,102,45,98,49,101,102,
                     45,57,50,55,49,53,54,51,51,100,51,49,98>> =>
                       <<"±HsD97Wxc9B1AJl+XEVwbzq4Io2MFAel7ETfz3fnd7U8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,55,49,98,101,50,97,50,45,
                     55,102,55,56,45,52,101,51,56,45,57,99,57,53,45,100,97,
                     100,50,52,56,102,51,50,98,57,53>> =>
                       <<"±JfiBj1w2LLc5yHug26bdRofbrjDUTk6szXPzh71Dx/8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,51,50,48,53,99,51,101,45,
                     98,101,57,51,45,52,52,52,98,45,56,98,54,101,45,99,99,57,
                     51,57,101,102,57,101,53,50,49>> =>
                       <<"±L4fplg4AL0+d75KlJdFp/gU9SnYOnA6oO4UemB5/XHo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,50,53,50,55,50,98,99,45,
                     48,99,98,52,45,52,98,51,102,45,56,55,53,98,45,49,51,56,
                     56,57,54,102,102,56,98,97,53>> =>
                       <<"±0niPf76AUHn/gq1Oz5v288iRQXyKN2eqGmppeYfunao=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,49,97,102,52,55,52,53,45,
                     49,53,97,101,45,52,54,48,101,45,57,53,99,99,45,54,55,56,
                     48,100,48,98,56,56,53,57,54>> =>
                       <<"±QbgF6nrAFOI1VumLs3RwKgg0Qmj5JImgLwiAhJOUoeQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,101,54,53,100,50,97,
                     45,49,54,98,100,45,52,57,100,56,45,56,100,53,48,45,101,
                     50,51,102,102,52,50,53,98,100,49,99>> =>
                       <<"±xK2zH1vrlsWWuT+IEwCdjw9N60crCZBfl+IoBR0PEUU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,98,52,100,55,52,48,45,
                     99,52,51,56,45,52,48,97,100,45,57,101,99,97,45,53,99,56,
                     57,48,50,49,56,48,53,54,50>> =>
                       <<"±85EwJ15RbuRZHGZvvOxpVsLFbb2U9KSttFMJDwWqrqg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,98,101,53,101,97,101,
                     100,45,100,52,56,48,45,52,100,100,102,45,57,101,99,102,
                     45,50,100,98,102,98,55,99,56,100,102,48,102>> =>
                       <<"±6k1x+6t9z9S3YDT66tzi1ziF4P3r8aDVCUpRNSQRkJ0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,98,50,49,99,52,55,45,
                     52,48,52,100,45,52,49,56,97,45,97,52,100,52,45,97,48,
                     101,50,52,50,100,102,102,51,51,55>> =>
                       <<"±6gHkmkb7yF2HneEXtGWve6Z7dmjj30Dn58fw06ysx78=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,98,51,50,49,98,98,97,45,
                     48,98,49,101,45,52,51,50,49,45,57,49,97,48,45,55,56,56,
                     101,55,49,99,57,56,97,57,101>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,97,50,50,51,54,100,97,45,
                     52,101,98,48,45,52,48,53,99,45,98,49,97,97,45,53,54,101,
                     56,100,52,48,51,50,56,57,51>> =>
                       <<"±kZZSPE9eDgfmuvMFW0ixLAEVyz/2XlYcQFDuXNNU82E=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,53,49,100,50,49,55,
                     100,45,52,48,48,50,45,52,48,99,54,45,98,102,54,54,45,97,
                     49,99,55,56,99,100,51,49,55,48,101>> =>
                       <<"±VMtuQfUODnOb83EzMMlz60a4vRBAw4+XiB8B/4my2KA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,51,50,52,100,55,52,
                     98,45,102,97,56,101,45,52,97,98,102,45,98,48,53,48,45,
                     48,55,53,99,53,102,51,98,102,52,101,99>> =>
                       <<"±7nFOj+NHNchl4aUVA/nbxYqBmKw8HNwolv6GEfWkKtM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,51,54,99,52,51,49,97,45,
                     48,48,101,57,45,52,52,57,98,45,98,98,57,98,45,53,99,102,
                     97,53,49,102,52,56,51,102,56>> =>
                       <<"±DCgvoBcpoqrgZmuy7+2882DKaec8ili1hqFrxz0etkE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,99,97,50,98,53,49,48,45,
                     101,54,48,55,45,52,55,50,99,45,56,48,49,97,45,55,57,48,
                     100,57,98,56,98,57,49,51,102>> =>
                       <<"±U6/SSs9Xqf39kAkVY+x5GfAzt236xezZPfmbbMj0C+U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,50,102,102,52,97,102,99,
                     45,52,57,101,101,45,52,101,56,100,45,56,102,100,51,45,
                     48,97,55,102,98,98,48,48,49,102,52,56>> =>
                       <<"±DF87yt+riWh6ijrQo2cj+l78GJ+pSbs3AglPEywWTW8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,98,98,97,54,55,49,101,
                     45,52,48,53,53,45,52,101,56,54,45,57,49,55,51,45,57,51,
                     54,57,50,57,52,99,52,52,99,48>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,99,101,57,49,97,100,98,
                     45,99,99,53,101,45,52,57,97,50,45,56,49,49,101,45,55,49,
                     48,55,56,55,51,53,100,50,50,49>> =>
                       <<"±WioYyaDNnqq9kTTmYsZ2MtcxKje2zbczljW+WHVPb7o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,50,54,49,97,99,49,97,45,
                     97,98,98,51,45,52,97,99,56,45,56,48,53,48,45,53,100,50,
                     98,53,54,97,98,101,53,97,52>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,99,101,55,50,97,100,
                     45,57,99,101,102,45,52,98,99,52,45,97,54,97,53,45,55,50,
                     49,54,52,53,49,54,99,97,48,48>> =>
                       <<"±PpWeZjWMbJDzpblYSWHuwjBjAo6P+RjpPzy5OIOxNGM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,57,97,57,98,51,49,55,
                     98,45,51,50,97,57,45,52,55,100,100,45,97,57,54,97,45,53,
                     48,49,51,49,97,102,57,102,57,56,57>> =>
                       <<"±63Nqm67YHf/sf9fzOKhKNVWOwyWAuWrP2mlOdIl1MZM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,50,57,51,48,98,48,97,45,
                     97,55,57,54,45,52,50,53,53,45,97,53,57,51,45,51,57,50,
                     49,52,51,52,54,51,100,102,97>> =>
                       <<"±YR6BsIC0dxwAKmQ152a7ztlER2TOPlwVtkb+j1Y9E0Y=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,54,49,97,56,52,48,
                     55,45,56,56,48,55,45,52,98,49,102,45,98,53,49,56,45,54,
                     54,99,102,100,99,49,99,54,49,56,49>> =>
                       <<"±KHpwdk0dgvgT6AGmUQWUX65MT8Wg17MAVlOJB3AUj6w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,51,102,53,99,56,102,52,
                     45,55,98,49,50,45,52,55,51,56,45,97,54,48,50,45,51,56,
                     99,48,101,48,99,53,49,102,53,100>> =>
                       <<"±8Za2LaK/fffwWPjPplC0YUnptip1ZTYUwZAR5dcXwLc=">>,
                   <<1,0,0,0,0,17,107,101,121,52>> =>
                       <<25,118,97,108,117,101,52>>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,57,50,56,56,98,48,45,
                     48,56,102,50,45,52,54,56,98,45,56,49,48,98,45,57,97,98,
                     57,54,57,99,50,99,53,49,49>> =>
                       <<"±sc7kNFBJq+h+mjwddPltIKcBbYlu6lUWGe+zfWlk+TM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,55,52,54,56,52,98,45,
                     98,50,99,100,45,52,54,100,54,45,97,57,101,98,45,54,102,
                     100,49,98,54,97,56,48,100,49,55>> =>
                       <<"±eZTLlP2b+mebFPSwyJFPm0s151BJBEGXk/dcagU6dSU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,98,50,100,57,99,98,45,
                     57,50,56,53,45,52,48,53,102,45,56,51,97,49,45,56,52,97,
                     55,57,56,99,52,55,102,50,53>> =>
                       <<"±387xLAMuEivCpBnT3VdzsmnbLZklJWQbpcrirDmflwc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,51,48,56,51,49,49,54,45,
                     54,100,57,101,45,52,56,98,97,45,56,50,101,57,45,51,101,
                     49,53,102,98,57,52,53,54,54,102>> =>
                       <<"±OvruTqQjPZnuQQ0aQPZvvFJdZEtFWGzg9s7l3zooEe0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,56,53,49,52,98,98,
                     100,45,52,49,56,57,45,52,51,57,56,45,98,54,97,102,45,49,
                     48,49,52,98,48,55,101,56,57,55,54>> =>
                       <<"±LmqnDdmCiC3eJQDkjRmNncrVd8C2SYbUk0y7jfpHzdM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,50,49,97,51,102,48,100,
                     45,49,55,48,56,45,52,55,102,100,45,98,102,102,50,45,100,
                     54,51,57,51,98,102,100,53,100,56,49>> =>
                       <<"±ai1IV9BwWEiK5tW6DM26ukhBKD8mvmcBNOuRrpppqy4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,99,55,52,50,51,97,48,
                     49,45,53,101,97,49,45,52,100,52,56,45,98,51,53,100,45,
                     99,52,53,102,98,100,99,50,56,57,99,97>> =>
                       <<"±TcsKxRQEj7MjBP/VXpfM4OMjnueCw0WGm/SBJqljKZs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,49,97,100,48,51,98,54,
                     45,99,48,57,101,45,52,53,51,102,45,56,50,50,99,45,53,98,
                     55,99,52,48,98,98,48,52,52,101>> =>
                       <<"±gq4oGUnrlZqKdysXyk35yT4WWwNbDlvxG0Qikw14En4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,51,99,56,102,51,48,45,
                     56,49,53,56,45,52,51,56,99,45,98,100,53,102,45,52,56,55,
                     54,102,102,49,55,53,97,56,50>> =>
                       <<"±K+o7KD3k5pPaDeFiX2Le7oseS8mhHJ+B0TSFMFoYpVM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,49,54,52,102,53,101,48,
                     45,52,102,97,52,45,52,57,49,52,45,57,53,53,102,45,99,55,
                     56,97,97,99,97,97,100,56,50,49>> =>
                       <<"±FwsS+5FRgzYY0o1uvSKHZ3JXJF9ZBQF/uMmZOTZkj+k=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,51,51,55,55,101,51,56,
                     45,50,97,98,49,45,52,48,54,56,45,97,56,54,102,45,101,57,
                     56,56,99,55,57,98,98,102,97,48>> =>
                       <<"±SHNWz3hXkviNzYZz/tDIkhgpFUaLVJCMSrZSfRN38Fk=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,101,49,54,55,57,97,
                     101,55,45,98,97,102,56,45,52,57,52,51,45,57,53,49,101,
                     45,97,99,98,54,50,52,53,98,50,53,50,50>> =>
                       <<"±0a8C0KfK6+pKcP4qX0uW4DzNvM/G74NPIDSTmCPqWzQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,101,48,98,97,52,48,49,45,
                     56,56,54,55,45,52,55,55,101,45,98,99,53,49,45,54,48,97,
                     51,48,56,48,97,99,49,53,54>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,102,99,51,50,51,99,99,
                     57,45,99,49,101,51,45,52,100,55,52,45,56,56,49,98,45,52,
                     100,55,50,54,50,98,52,53,50,48,54>> =>
                       <<"±uG4Sg0BC1X5vEsCUHT70DMX6hit6vUISiTYHCIZAqn0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,99,51,55,57,53,54,45,
                     56,53,102,57,45,52,54,100,54,45,98,100,100,98,45,50,102,
                     97,50,99,98,51,57,102,48,99,100>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,97,49,56,57,52,51,101,45,
                     50,53,50,52,45,52,48,102,54,45,97,51,54,100,45,51,97,55,
                     99,101,50,52,97,57,50,54,97>> =>
                       <<"±e0NGD3lmXnpP0FUsEioZWkNdbEIuHUg5tOAIKfOsHJ4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,100,98,97,98,55,98,
                     45,52,50,51,51,45,52,55,55,56,45,98,102,49,100,45,100,
                     52,53,49,100,55,102,100,101,53,48,54>> =>
                       <<"±9Gqdc57/6yYgGAv1NvZKWAUQC4jl3h2s3VRUwnWs7Rg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,49,101,56,97,57,56,55,
                     45,99,49,57,50,45,52,55,102,50,45,56,99,55,55,45,56,97,
                     53,51,101,101,54,54,100,100,55,102>> =>
                       <<"±WdSMQQFpALdIgZvO0y/+KY9OBT83PNVbWJMmTF6rsKU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,101,55,98,102,57,51,
                     45,99,101,53,99,45,52,54,52,53,45,98,48,55,54,45,52,53,
                     49,55,51,49,55,101,97,51,51,102>> =>
                       <<"±UKWP+ImlOd8oFfLOHXPSXDE7G/2lWq8H7GKuTaUi3Vc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,98,101,49,52,55,48,50,45,
                     101,100,53,55,45,52,97,97,55,45,98,100,99,56,45,54,50,
                     54,52,56,57,55,98,99,50,49,99>> =>
                       <<"±U/tsxfM/tPBJvxeatKDp7Q2eyn/JseD5gKoBg7csyuA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,102,102,101,55,54,56,54,
                     45,53,48,101,101,45,52,48,57,98,45,56,57,55,100,45,51,
                     54,100,51,99,101,57,55,49,101,56,53>> =>
                       <<"±nEQQKhQrzx7NQgK+WmgxCPoPpCyvjEbXdwN76wfuq0M=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,53,100,100,49,101,102,
                     102,101,45,100,98,55,98,45,52,101,50,50,45,97,48,102,49,
                     45,102,48,55,48,52,55,50,55,102,56,52,102>> =>
                       <<"±o+dYaGXghBIFipytqPxOAHAD2D96hKp4iBWGOzCGl6g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,98,52,53,54,97,55,48,45,
                     102,54,48,97,45,52,50,100,51,45,98,52,53,49,45,52,53,54,
                     53,53,102,49,56,57,98,53,53>> =>
                       <<"±L9NiBiC7HpeId5T7/6wDIv5BE4Lrgkb3HCt34U2XuV0=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,50,101,100,49,97,
                     54,50,45,49,100,99,56,45,52,101,49,101,45,57,50,50,53,
                     45,49,101,100,48,48,52,55,99,57,97,99,51>> =>
                       <<"±ia2gUm57Dc7qfdAtY9mc/5qiuPD5hn/dCQzcO2rBhjY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,49,52,54,53,99,48,45,
                     55,51,54,98,45,52,52,99,57,45,98,101,53,54,45,53,57,102,
                     51,52,49,98,49,54,55,52,50>> =>
                       <<"±88WFxLXdQL1/FlMW5MMeTd6WgtYwwFAhhND9m60xA5k=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,53,52,50,49,101,50, 
                     49,45,57,53,55,54,45,52,55,52,101,45,97,100,102,97,45,
                     48,50,100,51,49,49,51,102,52,51,98,55>> =>
                       <<"±DjfkckeFOwclJEI5tvNznGm4S28D62IXF3qG5VkzMCI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,54,100,101,100,98,
                     102,51,45,100,101,101,54,45,52,100,98,51,45,56,102,54,
                     101,45,100,97,101,100,100,52,55,97,56,57,51,48>> =>
                       <<"±JkUlBcl9KetKnhXpJ+tknaxeAijoppTF5JzqCbf3DCE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,102,99,98,99,49,50,97,45,
                     48,99,48,52,45,52,101,48,98,45,98,100,50,57,45,100,98,
                     102,51,98,57,102,52,51,52,52,102>> =>
                       <<"±en9Cl54/AKVlhG4vyHCKQI+6ERffLp3eeVei1HtpcfI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,52,51,57,51,55,99,50,45,
                     54,102,49,49,45,52,102,48,98,45,98,56,51,97,45,55,102,
                     53,97,53,51,97,50,98,51,57,49>> =>
                       <<"±CYdPaG1NEIdTBfNGiWUkgwnWjnNK+6C7KImuQroCBZ8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,52,52,100,102,99,48,101,
                     45,100,52,48,55,45,52,49,57,98,45,97,101,98,48,45,50,55,
                     102,99,52,49,51,56,51,99,97,50>> =>
                       <<"±GM4KW9NWVcRVmZhTAsjM+oObFK3R2lPPK+bQ8O4PU3A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,51,52,52,48,49,101,100,
                     45,53,101,50,51,45,52,101,49,49,45,56,52,50,102,45,56,
                     49,97,54,55,55,97,54,100,100,102,100>> =>
                       <<"±AEEYKhoChv2aJ9s3hjGyAWoq9usI3QzyCgfyihA6G9E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,48,99,50,101,102,97,102,
                     45,51,99,97,56,45,52,98,48,99,45,57,98,54,57,45,101,101,
                     56,48,49,102,56,57,98,54,50,49>> =>
                       <<"±bvhScrxrQZM4wSEe+Y9/dxm/kdXdk4kQM4LiX5haYvU=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,54,99,49,51,53,50,49,
                     57,45,98,102,48,54,45,52,48,50,50,45,98,53,52,50,45,56,
                     99,97,51,51,57,49,49,102,52,97,50>> =>
                       <<"±LHSX+C4XMTOLQVgPUgjknpBSIZOis+6+Os1kAcHpoF4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,102,57,102,56,97,101,
                     45,100,101,101,102,45,52,55,53,48,45,57,50,97,55,45,102,
                     56,98,53,48,53,99,100,98,101,56,99>> =>
                       <<"±eox/IEkhjon0BwDXym1jr2OCzBvqW71B3dEARoG2GwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,50,101,100,99,51,52,102,
                     45,51,52,99,102,45,52,97,97,101,45,98,50,52,48,45,55,50,
                     48,48,57,99,97,48,55,54,57,48>> =>
                       <<"±sR9j0l1MnbRG1JtRKL+k7C5BgGI2F3y8RLgK12SpS34=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,98,53,57,100,49,57,97,45,
                     50,98,100,100,45,52,50,102,99,45,57,100,101,54,45,98,54,
                     98,97,55,49,54,97,49,49,97,56>> =>
                       <<"±aTRrfKwDWdieB54ktGe45mrivxSvKCOLjCPh3M95FlA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,101,48,49,51,49,100,52,
                     45,49,48,99,57,45,52,48,49,101,45,57,99,52,50,45,98,100,
                     51,52,54,54,53,101,56,53,53,53>> =>
                       <<"±1xXeZvYiTl4h61YvRookf9pkMbFhV2svilFfeigJ38w=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,97,50,49,51,55,48,48,45,
                     51,49,49,100,45,52,52,51,97,45,57,50,54,53,45,102,100,
                     54,98,54,51,55,101,100,56,100,101>> =>
                       <<"±0I/otIqLJjX4jWwX8CA2vIrPxyWYep6ZCesgQFqVPdY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,53,48,49,52,50,48,49,45,
                     102,48,57,98,45,52,55,49,48,45,98,55,98,53,45,53,49,57,
                     101,51,52,49,56,49,48,101,49>> =>
                       <<"±sTVacB5NziSp3UZ5lmq1+nUfdoJ9aS9f8I+suOugsXw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,100,55,57,49,101,50,50,
                     45,48,48,48,51,45,52,50,50,50,45,57,55,55,57,45,99,101,
                     48,101,97,53,48,53,102,97,50,55>> =>
                       <<"±TWNBD2d5MfrAPpjWZfbj6W2wFVJqeYWGbqgGahP1Poo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,97,51,100,50,49,48,56,45,
                     99,102,98,52,45,52,53,97,57,45,57,57,57,56,45,57,55,102,
                     51,49,53,56,101,99,98,98,50>> =>
                       <<"±d7BcS3xkWf3eNb/blapTueA5WhEhdTgBkRKnuJoTMQY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,49,100,102,48,99,53,
                     102,54,45,99,101,102,54,45,52,57,102,57,45,98,56,49,57,
                     45,100,99,53,51,98,101,55,48,99,100,53,50>> =>
                       <<"±LHSX+C4XMTOLQVgPUgjknpBSIZOis+6+Os1kAcHpoF4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,55,52,101,56,50,98,45,
                     50,53,55,100,45,52,48,51,54,45,57,97,97,50,45,54,101,49,
                     57,53,101,55,55,54,54,48,98>> =>
                       <<"±RVC/FzufBua81ne3IWUySICiHs3ST36nPyJpAsRXMP4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,100,97,57,49,100,98,100,
                     45,56,98,51,98,45,52,57,51,50,45,97,51,55,49,45,55,101,
                     51,97,57,48,52,57,56,52,49,98>> =>
                       <<"±lxmJNXvjEbVr6uU3L/qHbc3sKcH5GVqy3ppwyCWvcbs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,51,56,56,100,102,49,
                     45,51,51,55,50,45,52,48,56,56,45,97,98,101,50,45,98,100,
                     48,100,57,53,100,48,102,101,57,51>> =>
                       <<"±fbo+xn8lBS1Ui5K0TX7cHcYF90kW+D2ZFlN8M3ah/5U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,99,50,101,56,53,99,57,45,
                     101,99,51,50,45,52,98,102,101,45,98,98,50,55,45,54,53,
                     51,49,56,101,101,98,100,53,54,100>> => 
                       <<"±aM6pYqCyNJnGWca3N7OWjsVhPprWdn0M//oYRc1kc84=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,100,98,51,48,52,55,54,45,
                     54,54,49,49,45,52,98,55,101,45,57,57,99,57,45,97,102,49,
                     102,52,100,50,55,55,99,52,50>> =>
                       <<"±pzLKqLUpmekPkTsvRziGj06xNIgcEVNkv/K08F+e6WM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,56,100,53,48,54,55,
                     51,45,53,52,56,101,45,52,101,102,99,45,56,57,56,100,45,
                     101,53,100,54,57,99,101,48,57,52,97,50>> =>
                       <<"±VWUbT/aEHxrahPBrO36zefeGTA+mQJejntWlMRziGBk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,56,97,99,101,97,52,48,45,
                     48,102,97,49,45,52,99,55,101,45,56,54,56,101,45,98,98,
                     102,100,54,52,52,56,48,48,48,50>> =>
                       <<"±irUGZ7yPkidGxU3/9Ahfguj8furjckCtBAG8TSeb5TM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,48,57,99,102,56,55,98,45,
                     50,101,52,55,45,52,50,55,53,45,98,97,99,54,45,53,102,50,
                     50,54,48,99,54,56,50,97,52>> =>
                       <<"±pEWdvcMCt2MjaO/027iqmHvk2y9GH+7fXXLXS/BB5Kg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,54,49,50,51,52,99,45,
                     54,49,51,101,45,52,101,51,56,45,97,97,52,48,45,56,52,55,
                     54,49,50,53,99,55,100,53,99>> =>
                       <<"±E8EU8LNEQ8G7Vn4jfSmjOkkAAf6fzAx1XUk/2nb+mwA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,97,56,52,57,52,50,102,45,
                     50,54,99,97,45,52,54,53,101,45,57,102,98,56,45,98,98,57,
                     50,57,99,51,54,99,99,52,98>> =>
                       <<"±rf7k7H5Yyonz35da7lX2FufqI1LX8n/SQRoI6NVJ6xQ=">>, 
                   <<1,0,0,0,0,161,98,109,116,95,48,56,101,49,98,102,50,48,
                     45,51,50,97,57,45,52,51,102,50,45,56,48,50,102,45,100,
                     57,56,48,53,100,100,99,55,53,50,102>> =>
                       <<"±TdwNnkviXMuhXBoNSzc6ob7XqBRJQK8+p0FHAVOlepo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,49,54,48,57,98,49,51,45,
                     98,52,102,101,45,52,48,102,99,45,97,97,53,54,45,100,53,
                     52,55,51,51,102,57,101,100,101,57>> =>
                       <<"±CAKOzhWdipmbo43iMnkV2UiaOAQC6I2pqmSGeYbk9MQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,53,50,56,51,57,52,50,45,
                     97,48,53,50,45,52,97,54,98,45,57,101,101,51,45,55,52,52,
                     55,52,99,56,50,49,53,98,50>> =>
                       <<"±OJ2mWouD0HJjPcUF/KcTfcjIBgqev60H5WhegyYyO6A=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,97,50,97,49,51,53,101,45,
                     101,53,102,48,45,52,53,50,54,45,57,48,102,48,45,48,97,
                     51,52,54,49,50,57,97,51,49,48>> =>
                       <<"±syflf6SuWg5DTsfbWbuyGuwsPEK0Kjek0WDiJho6HrQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,99,53,102,99,97,100,57,
                     45,50,102,50,54,45,52,56,97,53,45,57,100,101,98,45,50,
                     55,51,52,57,101,56,50,54,97,98,54>> =>
                       <<"±fhwADoFyzMLSb0SGXqFebWJ9M1cgu23jQR4VnCezYqk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,50,50,99,98,100,97,
                     45,97,55,101,52,45,52,101,57,99,45,97,49,99,102,45,55,
                     51,99,98,52,97,56,102,56,100,49,52>> =>
                       <<"±HmJldE8k/2qMvdVZ/VyK/GJyvnlhWW7/tptuo3i1oUM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,56,101,98,56,97,54,102, 
                     45,56,51,98,50,45,52,56,51,102,45,98,57,101,56,45,55,51,
                     98,49,48,49,53,48,57,50,53,57>> =>
                       <<"±Ic77RT9kL5UjNNarmFAE2QQkcdyLuvRm27lE9sTbcAM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,99,51,100,54,50,49,51,45,
                     99,57,97,48,45,52,51,52,52,45,56,53,54,97,45,99,53,100,
                     48,99,102,51,50,101,54,51,98>> =>
                       <<"±Jxxxbiq3vmuUNzdkUOYZHNRBzj9h+JdcA8P4EAdOX/4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,49,98,53,57,57,48,98,45,
                     48,51,50,102,45,52,52,49,55,45,97,55,48,51,45,101,52,55,
                     48,50,53,54,100,100,57,101,53>> =>
                       <<"±g1WRUy9UXio2dCb70sPfSXxRNZDMzhZvfnhdP5mP7mA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,52,97,50,100,54,49,56,45,
                     56,98,100,55,45,52,55,52,50,45,97,100,100,50,45,49,98,
                     101,57,51,102,51,100,99,97,100,54>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,48,57,97,100,57,52,
                     45,53,49,50,98,45,52,55,56,99,45,57,100,101,54,45,53,97,
                     50,99,49,56,101,52,57,57,97,52>> =>
                       <<"±XXcZqGgW277urOzSwTuamzYs9LAeXGD2RYQZP0OJCXw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,102,99,100,51,102,57,54,
                     45,101,102,51,49,45,52,98,50,56,45,98,52,56,55,45,98,55,
                     51,50,54,53,100,48,50,99,101,48>> =>
                       <<"±SBU4siTElnKJsWBStEFXsm6VD/Rfr3rJIzctOs84s/Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,52,98,99,101,55,97,54,45,
                     98,54,49,51,45,52,49,50,99,45,97,53,53,51,45,101,49,97,
                     97,101,51,51,52,52,53,102,102>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,97,50,55,52,101,48,52,45,
                     54,52,50,55,45,52,54,54,54,45,97,54,56,52,45,51,56,51,
                     99,52,51,102,48,101,57,53,48>> =>
                       <<"±IopVqjjkuzT5qwTfgVsdltB3jlRHyzHFwH1kT0anAzI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,48,48,51,57,51,97,57,45,
                     99,52,97,48,45,52,98,53,53,45,56,97,56,101,45,48,55,53,
                     53,100,50,100,53,49,99,55,50>> =>
                       <<"±echMFVhkBMmeYZp/jsS84p31WHgxSbwX+dkUCiwAl60=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,98,51,97,50,53,53,45,
                     55,97,50,54,45,52,100,49,98,45,57,99,49,99,45,56,48,97,
                     51,99,101,97,49,57,57,97,51>> =>
                       <<"±dN81mbJ49dKNlqbR9iukIha1Pkcx97vwAGz800jrpcs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,99,55,54,100,99,102,57,
                     45,51,48,52,54,45,52,98,55,48,45,98,101,52,49,45,99,50,
                     55,99,52,57,99,97,100,99,48,102>> =>
                       <<"±ilouuVY+RwKSeeUWfgnXt37eRR78Sxdc7CGGu9Y4+to=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,50,53,57,55,98,50,100,
                     45,100,53,52,56,45,52,49,56,50,45,97,53,56,97,45,51,49,
                     51,54,102,48,97,100,50,51,53,50>> =>
                       <<"±NdfQ23eD2IR+gheU9+6ICvFni3D2nDdLDM/KyKEushY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,52,49,53,52,54,100,
                     45,55,56,53,52,45,52,57,97,54,45,56,53,101,102,45,50,56,
                     53,49,55,97,101,48,55,57,102,55>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,54,97,53,53,56,49,52,45,
                     49,49,102,56,45,52,49,53,53,45,56,98,49,97,45,98,52,100,
                     54,54,56,98,101,100,102,48,54>> =>
                       <<"±ciDgzD0s+gsNczKyy8h0tDHKE38T1mj6AWyTX5a6dN4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,97,55,53,51,98,98,53,45,
                     98,97,101,99,45,52,100,52,52,45,56,57,102,99,45,51,55,
                     48,99,99,51,49,57,57,101,98,48>> =>
                       <<"±oqMU/lvgUtX21QNsGV0tQOASIfZXJoPVWmFR6mn3Y4g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,100,102,56,97,49,98,
                     45,101,49,56,49,45,52,55,49,54,45,56,97,54,57,45,57,98,
                     54,99,97,102,50,98,99,55,56,52>> =>
                       <<"±dBqUvFhkP27UYpbpBiMXlvd+mJ/VGGkcG10793YwCME=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,99,55,100,101,51,101,56,
                     45,48,50,56,98,45,52,100,54,55,45,56,99,97,53,45,101,97,
                     50,48,54,101,55,54,102,54,51,54>> =>
                       <<"±Z9SFCqP+4rmaSiMHXRkBCBo6WX9yp25SR0l8He0KtxE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,53,101,53,53,102,97,52,
                     45,51,53,97,100,45,52,48,54,57,45,98,51,97,55,45,52,99,
                     49,57,55,50,53,52,48,55,101,49>> =>
                       <<"±fAEUWhZN/8647sFOXl7S5JX+4XNW7HhuQVoBlwICOyI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,48,98,56,49,53,57,57,
                     102,45,57,49,100,102,45,52,50,50,98,45,97,56,99,48,45,
                     99,101,49,99,99,51,50,57,49,100,57,48>> =>
                       <<"±VsicAa88DuJbuc4MPqGbhdTPU+FqJWw/H2ou5DAqCnM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,97,53,98,99,98,101,45,
                     51,101,53,54,45,52,99,50,99,45,56,48,53,56,45,56,97,52,
                     102,56,99,51,101,54,48,55,53>> =>
                       <<"±VYgkRIgq1fYQ0LTqwtSMNLEi2E6nvt0KeaNavPd9fZM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,50,48,50,52,102,50,99,
                     45,101,51,55,57,45,52,54,48,57,45,97,101,54,51,45,57,48,
                     55,52,55,100,54,55,50,49,52,100>> =>
                       <<"±xdn0UDWTO047+ZAxHRX4WNZq611S9sWQYZHr2BA5Bvs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,55,49,97,99,52,54,100,45,
                     100,48,102,100,45,52,49,52,49,45,56,49,49,53,45,53,98,
                     56,55,54,53,57,100,100,52,50,99>> =>
                       <<"±lDcXfRzt4X48oFK8OFp8pG4h7UAla6boh+W7BmARjHU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,99,48,49,99,57,48,97,45,
                     53,53,49,49,45,52,51,50,98,45,56,53,52,57,45,56,54,100,
                     55,102,52,100,52,97,98,98,48>> =>
                       <<"±p1d4AGBrZBP442S5IY3K/JpRvWW6WrUAObvCHhlbs4s=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,55,52,56,100,101,
                     51,54,45,54,102,51,100,45,52,53,101,99,45,98,101,97,54,
                     45,49,102,99,52,49,51,57,49,56,56,50,56>> =>
                       <<"±FkI6+Aaceh8aMziWnMX3svvGvCkKTbNOZuMY317HBSQ=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,51,48,97,49,52,52,54,45,
                     52,101,54,101,45,52,55,98,48,45,56,102,57,55,45,54,99,
                     102,57,100,102,57,98,50,57,53,98>> =>
                       <<"±kXLKf75P2rDehrBYf2SEwbfBqXBnKiZJlY1xTkGb1To=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,50,52,51,101,57,99,102,
                     45,99,56,48,100,45,52,100,50,101,45,98,101,100,51,45,
                     102,50,57,50,102,49,53,49,57,57,99,99>> =>
                       <<"±/9HN6xdZaDI6rxp+PB2NMiE0cbDVxZoU4Ee86n9Xnog=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,97,101,100,100,56,49,50,
                     45,56,49,55,102,45,52,50,56,56,45,98,51,101,51,45,49,99,
                     100,53,100,97,57,54,49,53,99,100>> =>
                       <<"±qYH8poq9Eon1brICtyvu9TWI42639qR+djYNEaZ/2uM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,49,99,51,53,98,50,99,45,
                     52,52,57,99,45,52,50,55,97,45,98,57,50,50,45,101,55,100,
                     57,101,101,100,97,99,48,55,56>> =>
                       <<"±6wVRaWAUeT90HEkDCeY7/tDYgAa1AlqusWIlBoL7T2g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,54,57,49,100,102,48,56,
                     45,52,48,100,49,45,52,53,97,98,45,98,100,97,56,45,55,48,
                     98,52,100,50,100,100,53,101,50,57>> =>
                       <<"±pUfY4Hf0L76P6WvncrbIgjMB06sxxfzHrkpSsMaIfAE=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,54,100,52,98,54,57,56,45,
                     101,55,97,55,45,52,55,53,57,45,56,54,49,56,45,52,100,57,
                     52,102,102,99,49,52,98,97,102>> =>
                       <<"±baOQRpLUhdf/8sCZdlUF37G/mlkzE7oSw15tcyYiS1g=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,48,53,51,97,52,97,57,45,
                     100,57,102,48,45,52,102,52,55,45,56,100,54,102,45,57,52,
                     98,101,101,97,56,51,101,56,49,53>> =>
                       <<"±Wz0OUuypJcvCRMnd5G6b/sZs6uq2ajEIIPS3gRrp2As=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,97,54,50,49,55,98,101,45,
                     99,100,50,53,45,52,54,99,52,45,57,102,53,98,45,48,102,
                     56,97,57,50,57,99,102,101,52,101>> =>
                       <<"±04ocyIJKvZQYLIYi5r/Ya9DUJj0EI1rNTJrqWjBtuo8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,54,49,57,56,48,102,54,
                     45,54,57,98,99,45,52,55,49,52,45,56,53,53,53,45,52,99,
                     100,52,52,49,98,55,52,51,100,56>> =>
                       <<"±+5wqcuj8BEhiC4S4YUphLA9ciwW4F0juMxCZtUfnGe4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,56,57,100,49,53,102,98,
                     45,54,54,100,98,45,52,100,101,54,45,98,48,97,55,45,54,
                     99,50,52,56,49,56,49,101,57,50,99>> =>
                       <<"±AFQwST6gp7Heguy8nGul1HZKKg8/k0Q4imfC/G+Lp3o=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,56,53,48,55,55,100,52,45, 
                     97,51,101,98,45,52,53,54,51,45,57,50,56,99,45,54,55,53,
                     102,57,98,50,49,56,50,101,97>> =>
                       <<"±ydhtQcQgsWSzpImzEgjfBmwACYtGRo9kVKa/5h/cBKw=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,50,57,97,49,52,98,101,
                     100,45,57,101,55,102,45,52,52,97,54,45,97,55,48,101,45,
                     54,101,55,56,99,56,54,52,53,55,102,54>> =>
                       <<"±HoremVcJNMNvKwMUXHXUEEjiJzTmBoIIQsk1+5K6ZNU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,50,57,99,51,49,102,48,45,
                     49,48,53,102,45,52,99,55,100,45,57,51,55,55,45,97,54,52,
                     53,48,48,97,99,101,101,52,49>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,48,98,101,98,99,51,55,45,
                     54,48,102,52,45,52,50,52,100,45,98,98,49,56,45,98,97,48,
                     56,101,99,50,50,53,57,57,52>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,53,49,51,50,50,55,45,
                     55,53,100,100,45,52,51,48,100,45,98,49,50,50,45,52,102,
                     54,55,50,53,101,102,54,53,53,50>> => 
                       <<"±p4gk3DnLE0ivXeSrqpr+8l3A58BtpUJEwEDZ25zyPYI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,98,52,98,50,48,50,101,45,
                     48,54,101,56,45,52,52,97,52,45,98,57,48,51,45,48,55,97,
                     54,101,102,98,56,52,55,99,100>> =>
                       <<"±0sb34dv4UXiEhvzcpswz76I73ZJ7whymXIXqxSdtnco=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,51,100,100,48,54,57,57,
                     45,97,98,98,100,45,52,99,57,56,45,56,55,50,54,45,101,48,
                     48,50,98,100,102,100,98,48,98,56>> =>
                       <<"±huI+b12EujkIOL4YzGPX3gvNyoAxHFtPKdLMRxHPjdc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,98,97,100,99,97,57,49,45,
                     100,55,52,50,45,52,51,98,56,45,57,48,51,102,45,99,101,
                     50,99,57,56,49,55,102,52,50,99>> =>
                       <<"±AUwhw2O2S88iKClEUbSEKGQlRfD1eSDl3pc3rXLxAcs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,56,48,100,102,50,51,99,
                     45,56,55,55,99,45,52,56,101,97,45,98,98,101,54,45,55,98,
                     57,50,97,101,53,97,99,52,97,55>> =>
                       <<"±/c2SO4m1nHmBmnK3nrFVgLxJiPXcxeeB1acM5gFB6JI=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,101,56,51,50,56,51,
                     51,45,54,99,53,100,45,52,98,99,99,45,98,98,49,57,45,49,
                     100,51,51,57,57,54,51,55,53,53,102>> =>
                       <<"±6j0hO85K+ycxXtisVEPZwyme5IvaED2UhSAI7ETKiHg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,99,53,98,52,100,55,97,45,
                     50,99,52,102,45,52,99,57,51,45,98,98,101,54,45,56,102,
                     98,56,101,102,48,98,54,53,50,48>> =>
                       <<"±n1eI36dbLncHaoYkRd8Rmi2UOFtTckEl68EVX4TX/tA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,101,55,53,100,97,48,49,
                     45,49,99,56,55,45,52,100,56,101,45,98,54,98,57,45,51,57,
                     51,100,102,98,99,57,97,100,49,51>> =>
                       <<"±pbB9+aqW5h0r3T1PN9Z/IsPCpmFfCJU1ORKgzHgsVfc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,51,51,102,102,54,50,
                     56,56,45,55,51,53,98,45,52,56,48,53,45,98,97,101,49,45,
                     49,99,98,56,53,97,48,50,52,100,57,98>> =>
                       <<"±vlkODGTpBtLBfQBUMEAaRT51ayk9qPUyZds210e/KAY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,57,49,55,53,97,102,55,45,
                     56,51,48,49,45,52,97,97,51,45,97,99,56,55,45,97,53,100,
                     56,53,97,98,52,54,54,48,97>> =>
                       <<"±iGLMP7kmBgu0IxmKkSm5wK5zE2FbdjOSiXyjAZSJj3E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,55,102,98,98,101,51,97,
                     45,50,100,51,56,45,52,53,57,97,45,98,51,102,50,45,100,
                     55,57,99,57,100,49,52,49,98,49,49>> =>
                       <<"±DkYeuTcPjSHB5+0Yk6EAzlIrvY6S/Rf/sJb5R97UZ/A=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,50,101,98,98,98,97,
                     51,45,102,57,97,53,45,52,101,48,55,45,98,53,53,102,45,
                     53,52,51,51,49,50,52,102,48,99,99,56>> =>
                       <<"±osnMmljM4NWHYnM6y6DtVRa0ITNGzReDRYYdBCTsAt4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,98,55,51,97,52,98,99,45,
                     98,98,51,52,45,52,56,49,97,45,97,53,57,51,45,101,57,100,
                     101,98,101,102,56,51,102,49,56>> =>
                       <<"±ZtwZzzMmZdvOEdLBRrRrnZA3MgPVDVOykXMwRweEZDU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,48,50,56,97,102,56,48,45,
                     57,57,98,99,45,52,56,97,56,45,98,100,57,56,45,100,52,48,
                     49,57,98,98,50,50,99,54,56>> =>
                       <<"±7cAJzQyc1SGFTv0jEL0hbMYQwCbmMCuOyZZRRELSx4Y=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,98,54,48,49,102,102,101,
                     45,54,101,97,54,45,52,49,48,98,45,98,48,51,52,45,102,49,
                     97,102,97,57,98,53,53,52,53,54>> =>
                       <<"±OXYw+zzLu8815FBWSIAgO6JCV+hIjzzCX9wvJJEEQYo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,53,101,57,49,51,100,50,
                     45,50,56,52,98,45,52,98,53,54,45,56,55,101,97,45,99,97,
                     52,57,56,54,50,53,56,97,102,101>> =>
                       <<"±yLSPAdTfH02AauZ8bhOahWIF8bgl9O2aNj0KfcmRqWY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,50,98,99,102,49,57,50,45,
                     102,98,49,54,45,52,101,52,49,45,57,49,48,50,45,98,53,97,
                     98,101,57,99,100,98,52,99,48>> =>
                       <<"±Bne/YJVZuQzOGS5obN/xrG3y+Nj88HdTxBTCwS6BHlk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,98,51,50,101,57,54,53,45,
                     99,99,100,50,45,52,99,101,51,45,56,97,100,50,45,57,98,
                     50,55,55,49,97,97,49,102,55,50>> =>
                       <<"±EAahg9w/Ox3NfOlGBoQWshyUyIxC2vWKOQrCuXU8xJ8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,56,51,57,52,50,99,53,97,45,
                     51,51,55,97,45,52,50,56,56,45,57,56,49,49,45,101,48,102,
                     99,97,50,98,57,101,102,53,56>> =>
                       <<"±lP212mjPUZsIHPh2GaoBE/sRq0MLd52YFWpjPBGKXn4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,50,98,53,55,55,55,48,45,
                     97,55,53,99,45,52,98,50,57,45,57,98,50,48,45,98,50,101,
                     48,50,97,48,57,100,53,57,52>> =>
                       <<"±bUKxcVY86wudX4UUEUh2Y9Sc+COcyWIPq8elNiteaAo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,102,57,50,98,97,102,99,
                     45,49,55,97,48,45,52,99,54,51,45,98,97,56,54,45,53,54,
                     101,100,48,56,56,57,57,52,97,54>> =>
                       <<"±W/ICSy6iWs8CWZGlFLLvnT+CTugEewuwTjgtcoDi5L0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,102,54,98,100,57,48,54,
                     45,52,53,99,55,45,52,50,54,51,45,57,57,52,57,45,52,53,
                     49,55,53,48,100,101,101,55,99,50>> =>
                       <<"±UM/fVeb38C70y1aUyv9dvzSP3/0ouQFQ6m9st88Isa0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,99,97,101,101,100,49,53,
                     45,51,54,49,50,45,52,56,48,53,45,98,99,98,57,45,49,54,
                     56,48,50,101,97,102,98,101,52,102>> =>
                       <<"±TW6uepPxJmWzAMg6VvGt2FOngpt8Wlpo2kZqdy/U5I8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,51,54,52,97,101,48,45,
                     49,55,48,54,45,52,51,56,55,45,57,51,101,52,45,52,52,57,
                     55,101,102,49,52,55,101,97,54>> =>
                       <<"±C0eei7SBtaTQVe42Cthmj/+hcKJjgUcM5C7jZxyBHt4=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,100,57,101,102,99,49,57,
                     45,97,48,48,100,45,52,49,57,97,45,97,53,49,54,45,98,52,
                     53,54,101,101,52,50,50,57,50,51>> =>
                       <<"±LwfUPVpfqBQEqyz6pneh1W7IzSioFVdXrz2sEfxuvKI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,102,57,50,48,99,57,57,102,
                     45,100,98,54,98,45,52,51,50,99,45,57,52,100,57,45,101,
                     97,53,53,50,100,98,55,57,55,52,97>> =>
                       <<"±RC5fmqvQ2BQKfLZu3oLBkRzRTLduN4V/RotyMiauPOs=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,55,97,56,56,101,55,45,
                     50,101,57,102,45,52,57,55,49,45,56,49,102,55,45,56,98,
                     53,56,98,97,97,51,97,56,50,53>> =>
                       <<"±QkVhFjVutu0mxRtuRyR286ocony0pUwjsRme6leB8+4=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,55,51,97,51,52,54,
                     52,45,55,98,53,97,45,52,102,53,54,45,57,99,102,53,45,56,
                     56,100,51,97,48,98,48,48,100,57,101>> =>
                       <<"±lFSG8ll6AuYJ5Fcr/EC6e4aSnE4hFTqAK7m6kgxfrmY=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,57,49,57,98,55,57,101,45,
                     100,48,52,56,45,52,98,57,50,45,56,52,56,101,45,100,50,
                     102,52,50,48,55,57,53,99,53,55>> =>
                       <<"±yBqcV9r8mEwMBaPak34wEN7MJD6YAYitLaJ7Y6Tjczw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,49,97,102,99,99,98,102,101,
                     45,102,55,56,55,45,52,49,57,99,45,97,56,51,98,45,56,48,
                     99,48,102,49,100,50,98,54,56,50>> =>
                       <<"±qvcDJezWVkzD/4VbTwB+EnmdCDbSPjvqI+8uZX0qNMY=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,99,55,55,55,51,48,
                     50,45,98,53,51,50,45,52,52,101,100,45,57,53,48,98,45,97,
                     49,100,98,99,57,50,55,100,99,52,48>> =>
                       <<"±U8KROJkFfzI7178jx49vinJdbLn1p5hVBpXVzaJgMXo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,48,52,101,102,51,57,102,
                     45,51,54,97,51,45,52,98,98,102,45,97,100,97,100,45,97,
                     52,57,56,53,98,52,97,97,48,49,97>> =>
                       <<"±ngab0Rn8C1ofWMRuuG12TNMbKei1VWoHWF7p2n2N0MM=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,56,100,102,97,97,100,50,
                     45,48,52,102,97,45,52,56,101,52,45,97,52,99,51,45,50,48,
                     54,99,56,55,56,56,48,97,56,54>> =>
                       <<"±enOgbPFxugvGxwP6qmqKJhTXkMdRgMRQ+vgFg6RFdWk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,97,57,101,55,100,98,101,99,
                     45,102,50,100,97,45,52,55,98,50,45,57,57,57,56,45,50,
                     100,48,56,99,101,50,98,102,52,56,48>> =>
                       <<"±KnwdkSOJ1lKb+K3OEUzaEJe/jl8iTCmOWHc20fe23Yg=">>,
                   <<1,0,0,0,0,161,98,109,116,95,100,52,101,52,50,97,102,51,
                     45,53,54,55,48,45,52,50,53,51,45,57,50,100,98,45,57,97,
                     98,101,99,54,54,101,53,54,55,51>> =>
                       <<"±/aPyXOQNX5iJRqmstiPNfmAbtzMOlLyVKoUHJCKwIx8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,48,50,56,102,98,53,98,45,
                     52,101,52,101,45,52,101,99,49,45,56,53,99,52,45,57,48,
                     51,56,98,52,100,97,100,55,97,50>> =>
                       <<"±fYsclI9mNI3X2pjQGJVTQgh0mAP15NCmS3PE+uYlS58=">>,
                   <<1,0,0,0,0,161,98,109,116,95,55,98,102,97,98,50,98,52,45,
                     99,57,49,56,45,52,52,100,55,45,57,52,53,101,45,101,56,
                     55,48,51,55,51,50,101,48,48,54>> =>
                       <<"±Qob8wRwQSE2kNcU1I96GS8EY6VQtOwneiqX7ZasEFzc=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,51,57,102,99,48,53,49,45,
                     48,56,57,50,45,52,101,97,50,45,98,57,53,51,45,53,52,53,
                     49,57,52,98,100,55,51,98,55>> =>
                       <<"±CZZ+PZjAaHcTG8C0362NWYqD8vWrFPogkKRBPz+c9Sg=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,97,54,48,100,99,50,98,
                     48,45,49,97,54,55,45,52,50,50,97,45,98,97,51,49,45,100,
                     51,102,48,49,48,98,51,55,50,99,98>> =>
                       <<"±j0KwffQtTFXhxhSTJ2yj21A9R5K8BHbBXIZef22KnDw=">>,
                   <<1,0,0,0,0,161,98,109,116,95,101,101,51,102,101,48,99,50,
                     45,99,57,100,51,45,52,56,49,101,45,56,49,52,102,45,99,
                     52,102,54,48,51,53,101,97,100,57,51>> =>
                       <<"±Ic77RT9kL5UjNNarmFAE2QQkcdyLuvRm27lE9sTbcAM=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,52,101,56,55,49,49,54,
                     50,45,97,52,98,55,45,52,97,99,52,45,57,97,51,57,45,102,
                     50,49,101,99,50,98,51,53,99,49,55>> =>
                       <<"±K8S0iaQMdUyljmsXt8LqPDJEbPnuuZXUtv+6/Y4L1Vc=">>,
                   <<1,0,0,0,0,169,98,97,116,99,104,95,56,55,102,57,50,98,98,
                     100,45,50,51,99,57,45,52,100,102,99,45,98,56,49,97,45,
                     50,56,101,97,50,51,100,99,48,48,97,50>> =>
                       <<"±/Mk9SfjsThjpEHRYnyC6opvu5d5Md1r68qRiYQw1NMo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,53,53,100,102,97,99,51,
                     45,54,102,57,50,45,52,101,49,102,45,57,100,56,48,45,98,
                     99,49,56,102,57,50,52,99,52,57,99>> =>
                       <<"±dK3QLt/lL76CnLEievnkMITwqaE2aCNBcRpbqTue/6U=">>,
                   <<1,0,0,0,0,161,98,109,116,95,50,53,99,98,98,101,99,97,45,
                     56,101,54,56,45,52,101,102,100,45,57,55,101,97,45,51,56,
                     50,53,97,50,57,98,51,97,49,51>> =>
                       <<"±j8tA3ZiPnKpm4MAC3flPWA58CNc3ioqoh1rcUzSRvss=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,100,99,49,50,56,49,49,45,
                     100,53,48,97,45,52,56,52,50,45,98,57,52,57,45,49,56,48,
                     97,101,50,55,102,52,56,50,102>> =>
                       <<"±RX15zBUn0Epv6ydWGPmAiEHN6sL05Zg3FXYDwsEJrd8=">>,
                   <<1,0,0,0,0,161,98,109,116,95,98,100,102,54,101,101,100,
                     101,45,54,98,97,53,45,52,98,48,48,45,97,53,55,50,45,102,
                     53,97,49,57,98,48,98,52,98,99,54>> =>
                       <<"±eAx9j+9nE6wtl6AJIQY+WIqq/+61EePa2S0NlL9xLgI=">>,
                   <<1,0,0,0,0,161,98,109,116,95,51,54,51,55,49,53,98,98,45,
                     55,99,54,51,45,52,100,52,101,45,97,50,50,57,45,56,49,48,
                     102,57,99,99,55,50,51,98,102>> =>
                       <<"±holB3IaBg0q2NnLJzHTgTvNMKX1qsHrHFKqAHeOBKbo=">>,
                   <<1,0,0,0,0,161,98,109,116,95,54,54,54,99,99,53,98,98,45,
                     55,100,55,51,45,52,49,53,54,45,97,54,53,97,45,51,48,48,
                     51,50,51,97,53,49,52,50,50>> =>
                       <<"±xQR6oNmYiCMhUwRRIgd0OUCpUVsWi7i+lV+bqrgbow0=">>,
                   <<1,0,0,0,0,161,98,109,116,95,53,102,48,48,99,100,54,101,
                     45,50,99,101,100,45,52,99,100,101,45,97,100,57,51,45,50,
                     53,56,100,57,52,99,54,52,99,56,102>> =>
                       <<"±TXE4+z89fhFaSDk7WRAphZACE/ggquMSQWdgsaFggwU=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,100,101,101,55,51,97,100,
                     45,99,102,48,57,45,52,101,52,98,45,98,56,99,49,45,54,99,
                     52,57,52,99,54,52,48,50,98,52>> =>
                       <<"±PlVk4YAudy7EZorERg8UfmzavY3zKOC/9YsORFg+x8E=">>,
                   <<1,0,0,0,0,161,98,109,116,95,57,57,98,102,55,102,48,49,
                     45,49,99,55,101,45,52,52,98,54,45,98,48,51,57,45,50,97,
                     55,97,56,50,100,56,55,50,57,54>> =>
                       <<"±PRmDFxhv0Mv57N/PlcJkFAaEsJbsM2eQwgiPpt8PQws=">>,
                   <<1,0,0,0,0,161,98,109,116,95,52,57,102,54,49,53,51,56,45,
                     53,52,52,98,45,52,50,57,50,45,57,50,53,51,45,50,102,101,
                     99,50,57,97,51,53,102,57,51>> =>
                       <<"±+X6nB17PK3ZT1XDSgOGtBqm6zRUnoxhK79OtowtYdQA=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,49,101,55,97,49,55,100,
                     45,97,48,98,56,45,52,53,56,102,45,56,54,100,101,45,56,
                     102,54,50,49,98,49,102,48,102,101,98>> =>
                       <<"±srjGgmejuZpBU3mnP4rSkRimZ71kC6y7pF0Pm9fOx8I=">>,
                   <<1,0,0,0,0,161,98,109,116,95,99,102,97,49,52,97,54,102,
                     45,52,57,53,50,45,52,52,57,102,45,57,98,54,56,45,99,56,
                     102,54,50,55,52,49,57,100,102,51>> =>
                       <<"±znQVYfGoudkn8Pokr82U8ZTLfuLb5s9adhcdsyA6PJk=">>,
                   <<1,0,0,0,0,161,98,109,116,95,48,53,100,55,54,102,51,52,
                     45,49,97,99,52,45,52,55,48,53,45,98,98,102,51,45,49,
                     100,97,101,101,98,99,51,99,101,55,102>> =>
                       <<"±qoy1CSilO4n0jaCS2QYapIA2bWkgsc7yFcOPYm4ooXY=">>},
                 {mpt,<<230,217,101,112,173,19,38,216,254,114,105,188,167,
                        20,40,89,100,219,126,29,179,107,206,32,138,245,91,
                        193,223,160,82,0>>,
                      {db,aec_db_backends,contracts,
                          {gb_trees,{1,
                                     {<<230,217,101,112,173,19,38,216,254,114,105,188,167,20,
                                        40,89,100,219,126,29,179,107,206,32,138,245,91,193,223,
                                        160,82,0>>,
                                      [<<126,211,58,39,56,3,147,80,126,215,34,126,117,26,192,
                                         205,9,151,219,227,203,87,162,17,192,31,172,93,44,66,42,
                                         249>>,
                                       <<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,
                                       <<>>,<<>>,<<>>,<<>>],
                                      nil,nil}}}}}},
          <<>>,true,[],0,1}.

tx1() ->
    {signed_tx,{aetx,contract_call_tx,aect_call_tx,193,
                 {contract_call_tx,{id,account,
                                       <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                         114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                         253>>},
                                   1573,
                                   {id,contract,
                                       <<79,136,57,17,91,167,60,114,88,49,255,49,243,253,76,190,
                                         56,108,88,137,227,138,82,113,183,227,65,60,40,140,125,
                                         221>>},
                                   3,275790000000000,0,0,1579000,1500000000,
                                   <<43,17,174,232,104,9,27,47,1,169,98,97,116,99,104,95,55,
                                     48,56,54,52,55,57,55,45,101,97,53,55,45,52,55,102,48,45,
                                     98,102,102,99,45,99,98,51,48,49,100,57,98,50,51,55,50,
                                     177,49,122,66,53,50,120,101,56,67,72,77,86,113,67,43,87,
                                     69,115,98,107,49,85,49,49,49,122,114,90,111,104,65,88,
                                     49,118,98,101,49,121,70,85,57,89,119,61>>,
                                   [],
                                   <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                     114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                     253>>}},
           [<<48,214,2,81,134,9,98,195,88,188,65,146,151,223,6,254,
              96,225,17,197,68,64,120,31,102,215,174,202,103,228,
              224,121,183,114,252,17,27,7,58,212,201,71,0,12,224,
              140,164,156,140,114,98,155,66,48,110,139,28,167,113,
              202,173,72,146,4>>]}.

tx2() ->
    {signed_tx,{aetx,contract_call_tx,aect_call_tx,193,
                 {contract_call_tx,{id,account,
                                       <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                         114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                         253>>},
                                   1574,
                                   {id,contract,
                                       <<79,136,57,17,91,167,60,114,88,49,255,49,243,253,76,190,
                                         56,108,88,137,227,138,82,113,183,227,65,60,40,140,125,
                                         221>>},
                                   3,275790000000000,0,0,1579000,1500000000,
                                   <<43,17,174,232,104,9,27,47,1,169,98,97,116,99,104,95,49,
                                     56,49,98,53,100,97,102,45,51,100,53,56,45,52,101,53,102,
                                     45,98,97,53,50,45,97,51,97,49,50,53,48,56,97,97,97,99,
                                     177,53,121,71,74,122,81,52,79,108,85,90,119,116,109,85,
                                     49,122,43,99,72,113,110,115,52,117,115,66,52,97,122,78,
                                     76,100,55,84,116,76,71,55,103,54,71,77,61>>,
                                   [],
                                   <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                     114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                     253>>}},
           [<<224,150,92,150,212,122,132,231,32,68,13,85,75,249,
              176,217,237,216,129,48,175,83,54,172,78,194,53,65,20,
              247,34,229,52,128,59,187,51,119,61,160,115,114,84,63,
              187,173,195,12,170,112,233,40,188,38,22,26,219,47,
              212,138,132,88,248,0>>]}.

tx3() ->
    {signed_tx,{aetx,contract_call_tx,aect_call_tx,193,
                 {contract_call_tx,{id,account,
                                       <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                         114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                         253>>},
                                   1575,
                                   {id,contract,
                                       <<79,136,57,17,91,167,60,114,88,49,255,49,243,253,76,190,
                                         56,108,88,137,227,138,82,113,183,227,65,60,40,140,125,
                                         221>>},
                                   3,275790000000000,0,0,1579000,1500000000,
                                   <<43,17,174,232,104,9,27,47,1,169,98,97,116,99,104,95,101,
                                     53,55,57,55,48,101,56,45,99,99,50,97,45,52,56,50,100,45,
                                     98,57,53,102,45,102,51,53,101,56,48,102,55,51,51,53,55, 
                                     177,82,53,109,77,108,108,52,71,86,104,74,116,75,55,102,
                                     113,110,68,50,104,87,113,52,111,81,67,113,43,69,122,100,
                                     87,110,79,120,120,70,74,82,84,83,111,48,61>>,
                                   [],
                                   <<143,46,8,10,23,38,139,28,37,56,1,1,52,147,123,189,142,
                                     114,202,123,16,128,162,215,23,130,121,128,190,12,181,
                                     253>>}},
           [<<78,225,182,105,242,111,11,62,174,162,144,81,118,208,
              195,82,52,252,1,201,95,114,6,239,37,120,235,214,191,
              211,79,151,43,215,233,78,73,199,190,66,120,154,34,
              155,138,202,77,80,253,230,0,56,127,249,162,69,109,
              212,253,98,49,254,157,12>>]}. 

env() ->
    {env,5,
      <<18,251,106,214,238,189,3,192,7,26,141,181,229,18,200,
        101,253,61,73,180,120,143,60,164,126,161,219,109,29,161,
        240,145>>,
      aetx_transaction,[],[],undefined,undefined,undefined,
      1344889591367,false,471543,
      <<128,134,75,201,222,44,213,123,41,239,87,71,206,172,67,
        187,255,119,184,6,123,161,204,231,46,122,167,236,44,153,
        20,42>>,
      none,1628776599485,[]}.

test_contract_store() ->
    {store,#{},
           {mpt,<<230,217,101,112,173,19,38,216,254,114,105,188,167,
                  20,40,89,100,219,126,29,179,107,206,32,138,245,91,
                  193,223,160,82,0>>,
                {db,aec_db_backends,contracts,
                    {gb_trees,{1,
                               {<<230,217,101,112,173,19,38,216,254,114,105,188,167,20,
                                  40,89,100,219,126,29,179,107,206,32,138,245,91,193,223,
                                  160,82,0>>,
                                [<<126,211,58,39,56,3,147,80,126,215,34,126,117,26,192,
                                   205,9,151,219,227,203,87,162,17,192,31,172,93,44,66,42,
                                   249>>,
                                 <<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,<<>>,
                                 <<>>,<<>>,<<>>,<<>>],
                                nil,nil}}}}}}.

spend_tx1() ->
    {signed_tx,{aetx,spend_tx,aec_spend_tx,216,
                 {spend_tx,{id,account,
                               <<41,134,9,202,99,108,186,45,98,133,90,97,123,140,125,
                                 135,135,71,15,156,5,210,124,189,44,168,57,17,124,107,
                                 182,104>>},
                           {id,account,
                               <<41,134,9,202,99,108,186,45,98,133,90,97,123,140,125,
                                 135,135,71,15,156,5,210,124,189,44,168,57,17,124,107,
                                 182,104>>},
                           20000,19320000000000,471552,4970693,
                           <<"471542:kh_2BznAmAjLqtUNrV3rz4rc6vLWJ9Jyj6VKeHZcVfRiXdSHE8DNA:mh_L52dfY8GE6c2ksfm1QrkyuGyS5tBQZvF6Cju4f6VoP92mKbaQ:1628776602">>}},
           [<<39,31,195,192,7,126,229,144,36,223,35,112,46,45,179,
              113,224,158,248,67,203,71,54,198,9,125,0,110,37,240,
              159,37,51,136,184,157,52,95,174,165,195,246,126,32,
              252,75,107,105,64,75,127,59,57,100,144,91,220,22,169,
              209,168,55,127,15>>]}.

spend_tx2() ->
    {signed_tx,{aetx,spend_tx,aec_spend_tx,217,
                 {spend_tx,{id,account,
                               <<41,134,9,202,99,108,186,45,98,133,90,97,123,140,125,
                                 135,135,71,15,156,5,210,124,189,44,168,57,17,124,107,
                                 182,104>>},
                           {id,account,
                               <<41,134,9,202,99,108,186,45,98,133,90,97,123,140,125,
                                 135,135,71,15,156,5,210,124,189,44,168,57,17,124,107,
                                 182,104>>},
                           20000,19340000000000,471552,4970694,
                           <<"471542:kh_2BznAmAjLqtUNrV3rz4rc6vLWJ9Jyj6VKeHZcVfRiXdSHE8DNA:mh_2p1iP4my8kR2jWKSMT25tC7dsWhNrKePXrergRFsDPdCum5Hg6:1628776612">>}},
           [<<48,225,16,62,102,139,116,164,18,83,43,94,99,186,45,1,
              28,187,208,154,92,51,21,187,92,24,118,140,209,197,3,
              128,218,96,78,237,105,202,148,63,7,79,183,245,109,
              150,251,28,1,199,66,146,62,122,177,115,153,81,235,
              148,126,61,237,5>>]}.
spend_tx3() ->
    {signed_tx,{aetx,spend_tx,aec_spend_tx,217,
                 {spend_tx,{id,account,
                               <<123,165,128,147,131,246,100,117,15,97,130,34,168,78,88,
                                 42,65,254,96,207,243,24,178,217,137,8,51,36,193,197,
                                 115,214>>},
                           {id,account,
                               <<123,165,128,147,131,246,100,117,15,97,130,34,168,78,88,
                                 42,65,254,96,207,243,24,178,217,137,8,51,36,193,197,
                                 115,214>>},
                           20000,19340000000000,471552,5434113,
                           <<"471542:kh_2BznAmAjLqtUNrV3rz4rc6vLWJ9Jyj6VKeHZcVfRiXdSHE8DNA:mh_28LkyTDjYWA6kG7M73s3QmLzYbW76Pk8oPRGiebFTXzx4oU1Ch:1628776609">>}},
           [<<242,16,252,168,247,17,248,123,247,121,159,252,130,
              215,92,105,101,201,162,235,39,205,218,64,95,242,170,
              24,200,55,156,26,28,232,54,134,22,62,48,15,37,210,
              220,8,66,77,202,250,240,107,107,176,0,181,149,254,
              220,219,161,62,227,2,122,1>>]}.

spend_tx4() ->
    {signed_tx,{aetx,spend_tx,aec_spend_tx,217,
                 {spend_tx,{id,account,
                               <<185,163,137,253,5,211,34,121,113,90,33,196,136,47,134,
                                 34,48,1,177,25,137,34,139,125,58,237,175,177,72,239, 
                                 145,218>>},
                           {id,account,
                               <<185,163,137,253,5,211,34,121,113,90,33,196,136,47,134,
                                 34,48,1,177,25,137,34,139,125,58,237,175,177,72,239,
                                 145,218>>},
                           20000,19340000000000,471552,5413753,
                           <<"471542:kh_2BznAmAjLqtUNrV3rz4rc6vLWJ9Jyj6VKeHZcVfRiXdSHE8DNA:mh_2JbZzzFMZwdCZnAXrtoPV6Sed2Tkxjx9HvW4NufrFxvrSWHo9B:1628776599">>}},
           [<<212,84,254,119,94,125,136,61,129,30,155,9,90,247,131,
              30,61,187,151,252,232,106,246,48,82,160,194,119,104,
              115,102,39,83,203,223,46,116,223,75,110,11,32,134,84,
              139,12,240,7,54,211,220,160,130,215,214,19,70,115,
              211,46,200,140,28,5>>]}.

spend_tx5() ->
    {signed_tx,{aetx,spend_tx,aec_spend_tx,216,
                 {spend_tx,{id,account,
                               <<185,163,137,253,5,211,34,121,113,90,33,196,136,47,134,
                                 34,48,1,177,25,137,34,139,125,58,237,175,177,72,239, 
                                 145,218>>},
                           {id,account,
                               <<185,163,137,253,5,211,34,121,113,90,33,196,136,47,134,
                                 34,48,1,177,25,137,34,139,125,58,237,175,177,72,239,
                                 145,218>>},
                           20000,19320000000000,471552,5413754,
                           <<"471542:kh_2BznAmAjLqtUNrV3rz4rc6vLWJ9Jyj6VKeHZcVfRiXdSHE8DNA:mh_cu4PTF3rVgenUCB9i6pt4GpmVsaEjHSA8xTRoHGK2ynMPaVU5:1628776609">>}},
           [<<102,78,151,41,20,3,131,109,145,49,121,65,107,224,48,
              50,58,128,48,12,25,78,169,29,153,67,196,129,183,231,
              168,51,137,13,218,243,40,89,154,34,174,145,42,122,
              221,61,89,163,129,100,46,77,173,121,129,112,73,89,
              186,46,220,211,178,7>>]}.

spender_accounts() ->
    [{account,{id,account,
             <<41,134,9,202,99,108,186,45,98,133,90,97,123,140,125,
               135,135,71,15,156,5,210,124,189,44,168,57,17,124,107,
               182,104>>},
         51580983440000000000,4970692,0,undefined,undefined},
      {account,{id,account,
                  <<123,165,128,147,131,246,100,117,15,97,130,34,168,78,88,
                    42,65,254,96,207,243,24,178,217,137,8,51,36,193,197,
                    115,214>>},
              43125327079999999997,5434112,0,undefined,undefined},
      {account,{id,account,
                  <<185,163,137,253,5,211,34,121,113,90,33,196,136,47,134,
                    34,48,1,177,25,137,34,139,125,58,237,175,177,72,239,
                    145,218>>},
              43021166580000010000,5413752,0,undefined,undefined}].
