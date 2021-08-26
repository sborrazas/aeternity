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

repro_second_attempt_test_() ->
    [{"Repro issue second attempt",
      fun() ->
              Trees0 = aec_test_utils:create_state_tree(),
              AccountsTree =
                  lists:foldl(
                      fun(Acc, Accum) -> aec_accounts_trees:enter(Acc, Accum) end,
                      aec_trees:accounts(Trees0),
                      [owner_account()]),
              Trees = aec_trees:set_accounts(Trees0, AccountsTree),
              Txs = [contract_create_tx1(), contract_create_tx2()],
              {ok, ValidTxs, InvalidTxs, UpdatedTrees, _Events}
                   = aec_trees:apply_txs_on_state_trees(Txs, Trees,
                                                 env(), [{strict, true},
                                                         {dont_verify_signature, true}]),
              {valid, Txs} = {valid, ValidTxs},
              {invalid, []} = {invalid, InvalidTxs},
              RootHash = aec_trees:hash(UpdatedTrees),
              <<130,59,180,225,2,8,104,250,196,214,243,201,186,
                              191,207,99,114,205,148,139,35,172,164,103,29,
                              210,148,81,59,74,150,236>>
                  = RootHash,
              ok
      end}].

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

contract_create_tx2() ->
    {signed_tx,{aetx,contract_create_tx,aect_create_tx,1927,
                 {contract_create_tx,{id,account,
                                         <<238,242,24,217,253,245,82,194,111,147,126,51,143,49,
                                           146,62,225,140,135,32,23,95,85,249,113,151,175,36,100,
                                           46,203,36>>},
                                     7,
                                     <<249,3,249,70,3,160,39,147,224,0,198,24,136,107,35,174,
                                       172,69,160,206,181,148,51,48,73,63,88,250,86,187,40,45,
                                       166,140,101,144,0,92,192,185,3,203,185,2,230,254,8,59,
                                       226,96,0,55,1,7,55,0,2,3,17,240,234,120,157,38,0,7,12,6,
                                       251,3,77,80,79,76,76,95,65,76,82,69,65,68,89,95,67,76,
                                       79,83,69,68,47,24,138,0,7,12,10,251,3,85,86,79,84,69,95,
                                       79,80,84,73,79,78,95,78,79,84,95,75,78,79,87,78,85,0,45,
                                       74,144,144,0,94,0,85,0,12,1,0,68,252,35,6,4,0,6,4,3,17,
                                       101,165,224,15,254,45,152,134,27,0,55,0,119,1,2,130,254,
                                       61,30,137,104,0,55,0,55,6,55,4,119,119,119,135,2,55,0,
                                       55,1,151,64,103,7,119,135,2,55,0,55,1,7,7,103,71,0,7,71,
                                       0,12,2,130,12,2,132,12,2,134,12,2,136,39,12,8,12,2,138,
                                       12,2,140,12,2,142,12,2,144,12,2,146,39,12,12,0,254,68,
                                       214,68,31,0,55,3,55,4,119,119,119,135,2,55,0,55,1,151,
                                       64,103,7,119,135,2,55,0,55,1,7,55,0,12,3,100,40,28,0,0,
                                       2,3,17,170,192,194,134,33,0,7,12,6,251,3,81,84,73,84,76,
                                       69,95,83,84,82,73,78,71,95,84,79,95,76,79,78,71,12,3,
                                       111,129,236,40,28,2,0,2,3,17,170,192,194,134,33,0,7,12,
                                       12,251,3,105,68,69,83,67,82,73,80,84,73,79,78,95,83,84,
                                       82,73,78,71,95,84,79,95,76,79,78,71,89,2,142,26,14,144,
                                       47,0,85,2,146,40,30,130,0,0,40,30,132,2,0,40,30,134,4,0,
                                       40,30,136,6,0,26,6,138,2,26,6,140,4,1,3,63,254,77,156,
                                       24,31,0,55,1,71,0,135,2,55,0,55,1,7,26,10,0,144,47,24,
                                       144,0,7,12,4,1,3,175,130,0,1,0,63,43,24,0,0,68,252,35,0,
                                       2,2,2,0,254,91,217,102,241,0,55,0,103,71,0,7,1,2,144,
                                       254,99,148,233,122,0,55,0,55,4,119,119,119,135,2,55,0,
                                       55,1,151,64,12,2,130,12,2,132,12,2,134,12,2,136,39,12,8,
                                       0,254,101,165,224,15,2,55,1,135,2,55,3,71,0,71,0,7,55,2,
                                       71,0,71,0,55,0,8,61,0,2,4,70,54,0,0,0,70,54,2,0,2,70,54,
                                       4,0,4,100,2,175,95,159,1,129,7,144,211,46,25,234,167,
                                       219,219,55,250,129,14,31,45,153,215,59,109,186,61,184,
                                       101,110,252,55,123,107,137,202,37,89,0,2,4,1,3,63,70,54,
                                       0,0,0,70,54,2,0,2,99,175,95,159,1,129,183,254,84,145,
                                       210,213,72,160,136,49,244,49,196,55,129,101,61,196,206,
                                       24,83,77,65,184,175,254,35,221,136,25,125,112,0,2,1,3,
                                       63,254,137,212,173,55,0,55,0,55,0,85,0,46,10,144,144,94,
                                       0,85,0,68,252,35,6,4,2,4,4,3,17,101,165,224,15,254,170,
                                       192,194,134,2,55,1,119,7,62,4,0,0,254,176,62,49,176,0,
                                       55,1,71,0,23,47,24,144,0,0,254,184,66,128,192,0,55,1,71,
                                       0,23,32,24,146,0,0,254,201,246,159,157,0,55,0,135,2,55,
                                       0,55,1,7,1,2,140,254,236,109,65,225,0,55,0,7,1,3,4,254,
                                       240,234,120,157,0,55,0,23,26,10,0,140,8,62,140,2,4,1,3,
                                       127,70,58,2,0,0,89,0,34,32,2,0,184,221,47,15,17,8,59,
                                       226,96,17,118,111,116,101,17,45,152,134,27,21,116,105,
                                       116,108,101,17,61,30,137,104,37,103,101,116,95,115,116,
                                       97,116,101,17,68,214,68,31,17,105,110,105,116,17,77,156,
                                       24,31,49,118,111,116,101,100,95,111,112,116,105,111,110,
                                       17,91,217,102,241,21,118,111,116,101,115,17,99,148,233,
                                       122,33,109,101,116,97,100,97,116,97,17,101,165,224,15,
                                       45,67,104,97,105,110,46,101,118,101,110,116,17,137,212,
                                       173,55,45,114,101,118,111,107,101,95,118,111,116,101,17,
                                       170,192,194,134,57,46,83,116,114,105,110,103,46,108,101,
                                       110,103,116,104,17,176,62,49,176,37,104,97,115,95,118,
                                       111,116,101,100,17,184,66,128,192,37,105,115,95,97,117,
                                       116,104,111,114,17,201,246,159,157,49,99,108,111,115,
                                       101,95,104,101,105,103,104,116,17,236,109,65,225,29,118,
                                       101,114,115,105,111,110,17,240,234,120,157,37,105,115,
                                       95,99,108,111,115,101,100,130,47,0,133,54,46,48,46,49,0>>,
                                     #{abi => 3,vm => 7},
                                     113540000000000,0,0,1579000,1000000000,
                                     <<43,17,68,214,68,31,59,75,213,78,97,109,101,32,102,111,
                                       114,32,116,104,101,32,110,101,119,32,195,166,116,101,
                                       114,110,105,116,121,32,67,111,110,116,114,105,98,117,
                                       116,105,111,110,32,80,114,111,103,114,97,109,33,32,240,
                                       159,145,164,1,126,84,104,101,32,195,166,99,111,115,121,
                                       115,116,101,109,32,105,115,32,108,111,111,107,105,110,
                                       103,32,102,111,114,32,97,32,110,97,109,101,32,102,111,
                                       114,32,105,116,115,32,110,101,119,101,115,116,32,112,
                                       108,97,116,102,111,114,109,32,102,111,114,32,111,112,
                                       101,110,45,115,111,117,114,99,101,32,99,111,109,109,117,
                                       110,105,116,121,32,99,111,108,108,97,98,111,114,97,116,
                                       105,111,110,33,32,226,173,144,239,184,143,240,159,145,
                                       168,226,128,141,240,159,154,128,240,159,166,132,240,159,
                                       140,136,1,92,104,116,116,112,115,58,47,47,102,111,114,
                                       117,109,46,97,101,116,101,114,110,105,116,121,46,99,111,
                                       109,47,116,47,99,104,111,111,115,101,45,121,111,117,114,
                                       45,110,97,109,101,45,108,101,116,115,45,102,105,110,100,
                                       45,97,45,110,97,109,101,45,102,111,114,45,116,104,101,
                                       45,110,101,119,45,99,111,109,109,117,110,105,116,121,45,
                                       99,111,110,116,114,105,98,117,116,111,114,45,112,114,
                                       111,103,114,97,109,47,57,55,49,50,175,130,0,1,0,63,47,
                                       42,0,21,195,134,114,109,121,2,33,68,101,118,70,111,114,
                                       99,101,4,33,83,112,195,166,99,105,97,108,6,37,77,121,99,
                                       195,134,108,105,117,109,8,25,195,134,115,116,97,114,10,
                                       45,105,110,110,111,118,195,166,116,105,111,110,12,37,
                                       195,134,117,112,104,111,114,105,97,14,41,195,134,110,97,
                                       114,99,114,121,112,116,16,33,195,134,85,110,105,116,101,
                                       100,18,17,195,134,118,101,20,25,195,134,108,105,111,110,
                                       22,33,84,104,101,32,102,195,166,109,24,17,83,195,134,83,
                                       26,105,66,73,84,76,32,58,32,66,114,105,110,103,32,73,
                                       100,101,97,115,32,116,111,32,108,105,102,101,28,45,74,
                                       195,166,110,105,115,115,195,166,114,121,30,53,195,134,
                                       32,195,134,114,116,105,108,108,101,114,121,32,101,65,69,
                                       32,67,111,109,109,117,110,105,116,121,32,83,111,99,105,
                                       97,108,32,77,111,110,101,121,34,61,84,104,101,32,84,195,
                                       166,115,107,32,70,111,114,99,101,36,33,84,97,103,32,116,
                                       195,166,109,38,33,84,195,166,109,119,48,114,107,40,45,
                                       84,104,101,32,195,166,45,84,101,97,109,42,37,84,104,195,
                                       166,32,67,117,108,116,44,29,83,107,195,166,108,108,115,
                                       46,49,84,104,101,32,86,105,108,108,195,166,103,101,48,
                                       29,195,166,117,110,105,116,121,50,49,84,104,101,32,67,
                                       111,109,109,117,110,195,166,52,41,84,104,101,32,80,195,
                                       166,112,108,101,54,49,84,104,101,32,66,195,166,116,116,
                                       101,114,121,56,57,84,104,101,32,71,195,166,116,104,101,
                                       114,105,110,103,58,53,84,104,101,32,67,111,109,109,105,
                                       116,116,195,166,60,37,83,80,195,134,82,84,65,78,83,62,
                                       37,65,69,32,78,105,110,106,97,115,64,41,195,134,32,76,
                                       101,103,105,111,110,115,66,41,71,117,195,166,114,100,
                                       105,97,110,115,68,29,66,195,170,195,166,115,116,70,33,
                                       195,134,45,83,113,117,97,100,72,29,195,134,32,83,101,97,
                                       108,74,29,195,134,82,73,65,78,83,76,81,76,195,166,103,
                                       105,111,110,32,111,102,32,195,166,116,101,114,110,105,
                                       116,121,78,45,195,166,116,101,114,110,105,115,116,97,
                                       115,80,57,195,166,116,101,114,110,97,108,32,115,111,117,
                                       108,115,82,45,195,166,115,116,114,111,110,97,117,116,
                                       115,175,130,0,1,1,27,111,131,7,75,205>>,
                                     0}},
           [<<226,59,12,248,95,79,57,82,10,205,121,212,208,49,6,7,
              246,146,68,97,188,15,30,29,40,201,251,139,23,178,78,
              211,230,130,22,190,153,127,126,13,55,45,102,204,14,
              39,203,73,212,143,80,229,70,213,123,251,29,248,71,
              121,235,94,143,10>>]}.

contract_create_tx1() ->
    {signed_tx,{aetx,contract_create_tx,aect_create_tx,1926,
                 {contract_create_tx,{id,account,
                                         <<238,242,24,217,253,245,82,194,111,147,126,51,143,49,
                                           146,62,225,140,135,32,23,95,85,249,113,151,175,36,100,
                                           46,203,36>>},
                                     6,
                                     <<249,3,249,70,3,160,39,147,224,0,198,24,136,107,35,174,
                                       172,69,160,206,181,148,51,48,73,63,88,250,86,187,40,45,
                                       166,140,101,144,0,92,192,185,3,203,185,2,230,254,8,59,
                                       226,96,0,55,1,7,55,0,2,3,17,240,234,120,157,38,0,7,12,6,
                                       251,3,77,80,79,76,76,95,65,76,82,69,65,68,89,95,67,76,
                                       79,83,69,68,47,24,138,0,7,12,10,251,3,85,86,79,84,69,95,
                                       79,80,84,73,79,78,95,78,79,84,95,75,78,79,87,78,85,0,45,
                                       74,144,144,0,94,0,85,0,12,1,0,68,252,35,6,4,0,6,4,3,17,
                                       101,165,224,15,254,45,152,134,27,0,55,0,119,1,2,130,254,
                                       61,30,137,104,0,55,0,55,6,55,4,119,119,119,135,2,55,0,
                                       55,1,151,64,103,7,119,135,2,55,0,55,1,7,7,103,71,0,7,71,
                                       0,12,2,130,12,2,132,12,2,134,12,2,136,39,12,8,12,2,138,
                                       12,2,140,12,2,142,12,2,144,12,2,146,39,12,12,0,254,68,
                                       214,68,31,0,55,3,55,4,119,119,119,135,2,55,0,55,1,151,
                                       64,103,7,119,135,2,55,0,55,1,7,55,0,12,3,100,40,28,0,0,
                                       2,3,17,170,192,194,134,33,0,7,12,6,251,3,81,84,73,84,76,
                                       69,95,83,84,82,73,78,71,95,84,79,95,76,79,78,71,12,3,
                                       111,129,236,40,28,2,0,2,3,17,170,192,194,134,33,0,7,12,
                                       12,251,3,105,68,69,83,67,82,73,80,84,73,79,78,95,83,84,
                                       82,73,78,71,95,84,79,95,76,79,78,71,89,2,142,26,14,144,
                                       47,0,85,2,146,40,30,130,0,0,40,30,132,2,0,40,30,134,4,0,
                                       40,30,136,6,0,26,6,138,2,26,6,140,4,1,3,63,254,77,156,
                                       24,31,0,55,1,71,0,135,2,55,0,55,1,7,26,10,0,144,47,24,
                                       144,0,7,12,4,1,3,175,130,0,1,0,63,43,24,0,0,68,252,35,0,
                                       2,2,2,0,254,91,217,102,241,0,55,0,103,71,0,7,1,2,144,
                                       254,99,148,233,122,0,55,0,55,4,119,119,119,135,2,55,0,
                                       55,1,151,64,12,2,130,12,2,132,12,2,134,12,2,136,39,12,8,
                                       0,254,101,165,224,15,2,55,1,135,2,55,3,71,0,71,0,7,55,2,
                                       71,0,71,0,55,0,8,61,0,2,4,70,54,0,0,0,70,54,2,0,2,70,54,
                                       4,0,4,100,2,175,95,159,1,129,7,144,211,46,25,234,167,
                                       219,219,55,250,129,14,31,45,153,215,59,109,186,61,184,
                                       101,110,252,55,123,107,137,202,37,89,0,2,4,1,3,63,70,54,
                                       0,0,0,70,54,2,0,2,99,175,95,159,1,129,183,254,84,145,
                                       210,213,72,160,136,49,244,49,196,55,129,101,61,196,206,
                                       24,83,77,65,184,175,254,35,221,136,25,125,112,0,2,1,3,
                                       63,254,137,212,173,55,0,55,0,55,0,85,0,46,10,144,144,94,
                                       0,85,0,68,252,35,6,4,2,4,4,3,17,101,165,224,15,254,170,
                                       192,194,134,2,55,1,119,7,62,4,0,0,254,176,62,49,176,0,
                                       55,1,71,0,23,47,24,144,0,0,254,184,66,128,192,0,55,1,71,
                                       0,23,32,24,146,0,0,254,201,246,159,157,0,55,0,135,2,55,
                                       0,55,1,7,1,2,140,254,236,109,65,225,0,55,0,7,1,3,4,254,
                                       240,234,120,157,0,55,0,23,26,10,0,140,8,62,140,2,4,1,3,
                                       127,70,58,2,0,0,89,0,34,32,2,0,184,221,47,15,17,8,59,
                                       226,96,17,118,111,116,101,17,45,152,134,27,21,116,105,
                                       116,108,101,17,61,30,137,104,37,103,101,116,95,115,116,
                                       97,116,101,17,68,214,68,31,17,105,110,105,116,17,77,156,
                                       24,31,49,118,111,116,101,100,95,111,112,116,105,111,110,
                                       17,91,217,102,241,21,118,111,116,101,115,17,99,148,233,
                                       122,33,109,101,116,97,100,97,116,97,17,101,165,224,15,
                                       45,67,104,97,105,110,46,101,118,101,110,116,17,137,212,
                                       173,55,45,114,101,118,111,107,101,95,118,111,116,101,17,
                                       170,192,194,134,57,46,83,116,114,105,110,103,46,108,101,
                                       110,103,116,104,17,176,62,49,176,37,104,97,115,95,118,
                                       111,116,101,100,17,184,66,128,192,37,105,115,95,97,117,
                                       116,104,111,114,17,201,246,159,157,49,99,108,111,115,
                                       101,95,104,101,105,103,104,116,17,236,109,65,225,29,118,
                                       101,114,115,105,111,110,17,240,234,120,157,37,105,115,
                                       95,99,108,111,115,101,100,130,47,0,133,54,46,48,46,49,0>>,
                                     #{abi => 3,vm => 7},
                                     113520000000000,0,0,1579000,1000000000,
                                     <<43,17,68,214,68,31,59,75,209,78,97,109,101,32,102,111,
                                       114,32,116,104,101,32,110,101,119,32,195,166,116,101,
                                       114,110,105,116,121,32,67,111,110,116,114,105,98,117,
                                       116,111,114,32,80,114,111,103,114,97,109,33,32,240,159,
                                       145,164,1,126,84,104,101,32,195,166,99,111,115,121,115,
                                       116,101,109,32,105,115,32,108,111,111,107,105,110,103,
                                       32,102,111,114,32,97,32,110,97,109,101,32,102,111,114,
                                       32,105,116,115,32,110,101,119,101,115,116,32,112,108,97,
                                       116,102,111,114,109,32,102,111,114,32,111,112,101,110,
                                       45,115,111,117,114,99,101,32,99,111,109,109,117,110,105,
                                       116,121,32,99,111,108,108,97,98,111,114,97,116,105,111,
                                       110,33,32,226,173,144,239,184,143,240,159,145,168,226,
                                       128,141,240,159,154,128,240,159,166,132,240,159,140,136,
                                       1,92,104,116,116,112,115,58,47,47,102,111,114,117,109,
                                       46,97,101,116,101,114,110,105,116,121,46,99,111,109,47,
                                       116,47,99,104,111,111,115,101,45,121,111,117,114,45,110,
                                       97,109,101,45,108,101,116,115,45,102,105,110,100,45,97,
                                       45,110,97,109,101,45,102,111,114,45,116,104,101,45,110,
                                       101,119,45,99,111,109,109,117,110,105,116,121,45,99,111,
                                       110,116,114,105,98,117,116,111,114,45,112,114,111,103,
                                       114,97,109,47,57,55,49,50,175,130,0,1,0,63,47,42,0,21,
                                       195,134,114,109,121,2,33,68,101,118,70,111,114,99,101,4,
                                       33,83,112,195,166,99,105,97,108,6,37,77,121,99,195,134,
                                       108,105,117,109,8,25,195,134,115,116,97,114,10,45,105,
                                       110,110,111,118,195,166,116,105,111,110,12,37,195,134,
                                       117,112,104,111,114,105,97,14,41,195,134,110,97,114,99,
                                       114,121,112,116,16,33,195,134,85,110,105,116,101,100,18,
                                       17,195,134,118,101,20,25,195,134,108,105,111,110,22,33,
                                       84,104,101,32,102,195,166,109,24,17,83,195,134,83,26,
                                       105,66,73,84,76,32,58,32,66,114,105,110,103,32,73,100,
                                       101,97,115,32,116,111,32,108,105,102,101,28,45,74,195,
                                       166,110,105,115,115,195,166,114,121,30,53,195,134,32,
                                       195,134,114,116,105,108,108,101,114,121,32,101,65,69,32,
                                       67,111,109,109,117,110,105,116,121,32,83,111,99,105,97,
                                       108,32,77,111,110,101,121,34,61,84,104,101,32,84,195,
                                       166,115,107,32,70,111,114,99,101,36,33,84,97,103,32,116,
                                       195,166,109,38,33,84,195,166,109,119,48,114,107,40,45,
                                       84,104,101,32,195,166,45,84,101,97,109,42,37,84,104,195,
                                       166,32,67,117,108,116,44,29,83,107,195,166,108,108,115,
                                       46,49,84,104,101,32,86,105,108,108,195,166,103,101,48,
                                       29,195,166,117,110,105,116,121,50,49,84,104,101,32,67,
                                       111,109,109,117,110,195,166,52,41,84,104,101,32,80,195,
                                       166,112,108,101,54,49,84,104,101,32,66,195,166,116,116,
                                       101,114,121,56,57,84,104,101,32,71,195,166,116,104,101,
                                       114,105,110,103,58,53,84,104,101,32,67,111,109,109,105,
                                       116,116,195,166,60,37,83,80,195,134,82,84,65,78,83,62,
                                       37,65,69,32,78,105,110,106,97,115,64,41,195,134,32,76,
                                       101,103,105,111,110,115,66,41,71,117,195,166,114,100,
                                       105,97,110,115,68,29,66,195,170,195,166,115,116,70,33,
                                       195,134,45,83,113,117,97,100,72,29,195,134,32,83,101,97,
                                       108,74,29,195,134,82,73,65,78,83,76,81,76,195,166,103,
                                       105,111,110,32,111,102,32,195,166,116,101,114,110,105,
                                       116,121,78,45,195,166,116,101,114,110,105,115,116,97,
                                       115,80,57,195,166,116,101,114,110,97,108,32,115,111,117,
                                       108,115,82,45,195,166,115,116,114,111,110,97,117,116,
                                       115,175,130,0,1,1,27,111,131,7,75,203>>,
                                     0}},
           [<<26,130,147,20,90,64,199,35,231,191,110,23,216,226,
              220,128,16,32,97,232,88,76,9,9,221,195,67,37,46,129,
              80,62,231,74,172,75,47,14,71,228,91,249,135,90,101,
              116,83,232,76,19,15,31,213,149,110,46,185,155,253,64,
              141,1,251,15>>]}.

owner_account() ->
    {account,{id,account,
             <<238,242,24,217,253,245,82,194,111,147,126,51,143,49,
               146,62,225,140,135,32,23,95,85,249,113,151,175,36,100,
               46,203,36>>},
         2999004342000000000,5,0,undefined,undefined}.
