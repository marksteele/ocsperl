-module(ocsperl).
-export([
         check/3
        ]).

-compile([no_native]).

-define(NOT_LOADED, not_loaded(?LINE)).

-on_load(init/0).

init() ->
  Path = case application:get_env(code,sopath) of
           {ok, CodePath} ->
             CodePath;
           _ ->
             case code:priv_dir(?MODULE) of
               {error, _} ->
                 EbinDir = filename:dirname(code:which(?MODULE)),
                 AppPath = filename:dirname(EbinDir),
                 filename:join(AppPath, "priv");
               CodePath ->
                 CodePath
             end
         end,
  erlang:load_nif(filename:join(Path, ?MODULE), 0).

check(Cert, CACert, Issuer) when is_list(Cert), is_list(CACert), is_list(Issuer) ->
  nif_check_ocsperl(Cert, CACert, Issuer);
check(Cert, CACert, Issuer) when is_binary(Cert), is_binary(CACert), is_binary(Issuer) ->
  check(binary_to_list(Cert), binary_to_list(CACert), binary_to_list(Issuer)).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

nif_check_ocsperl(_, _, _) ->
  ?NOT_LOADED.
