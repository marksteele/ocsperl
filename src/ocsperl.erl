-module(ocsperl).
-export([
         check/3
        ]).

-compile([no_native]).

-define(NOT_LOADED, not_loaded(?LINE)).

-on_load(init/0).

init() ->
  PrivDir = case code:priv_dir(?MODULE) of
              {error, _} ->
                EbinDir = filename:dirname(code:which(?MODULE)),
                AppPath = filename:dirname(EbinDir),
                filename:join(AppPath, "priv");
              Path ->
                Path
            end,
  erlang:load_nif(filename:join(PrivDir, "ocsperl"), 0).

-spec check(Cert::list(), CACert::list(), Issuer::list()) -> good | revoked | error.
check(Cert, CACert, Issuer) ->
  nif_check_ocsperl(Cert, CACert, Issuer).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

nif_check_ocsperl(_, _, _) ->
  ?NOT_LOADED.
