%%% -*- erlang-indent-level:4; indent-tabs-mode: nil -*-
%%% =============================================================================
%%% @copyright 2018-21, Aeternity Anstalt
%%% @doc
%%%    Server to monitor and execute maintenance_mode settings/transitions
%%% @end
%%% =============================================================================

-module(aeu_oam).

-behaviour(gen_server).

-export([ start_link/0 ]).

-export([ init/1
        , handle_call/3
        , handle_cast/2
        , handle_info/2
        , terminate/2
        , code_change/3 ]).

-define(SERVER, ?MODULE).

-record(st, {current = false :: boolean()}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    aec_events:subscribe(update_config),
    {ok, MMode} = aeu_env:find_config([<<"system">>, <<"maintenance_mode">>],
                                      [user_config, schema_default]),
    set_app_permissions(MMode),
    {ok, #st{current = MMode}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_request}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info({gproc_ps_event, update_config,
             #{info := #{<<"system">> :=
                             #{<<"maintenance_mode">> := New}}}}, #st{current = Cur} = St)
  when New =/= Cur ->
    execute_callbacks(New),
    set_app_permissions(New),
    {noreply, St#st{current = New}};
handle_info(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, _St) ->
    ok.

code_change(_FromVsn, St, _Extra) ->
    {ok, St}.

set_app_permissions(MMode) when is_boolean(MMode) ->
    AppFlags = setup:find_env_vars(ae_run_in_maintenance_mode),
    Permissions = case MMode of
                      true ->
                          AppFlags;
                      false ->
                          [{App, true} || {App,_} <- AppFlags]
                  end,
    [application:permit(App, Flag) || {App, Flag} <- Permissions],
    ok.

execute_callbacks(MMode) ->
    Mode = if MMode -> ae_mmode_on;
              true  -> ae_mmode_off
           end,
    Hooks = setup:find_hooks(Mode),
    setup:run_selected_hooks(Hooks).
