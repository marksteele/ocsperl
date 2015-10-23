#include "erl_nif.h"
#include <ocsp.h>

static ERL_NIF_TERM
erlang_ocsperl_check(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  unsigned int cert_length, cacert_length, issuer_length, ret;

  if (!enif_get_list_length(env,argv[0],&cert_length)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_list_length(env,argv[1],&cacert_length)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_list_length(env,argv[2],&issuer_length)) {
    return enif_make_badarg(env);
  }

  char cert[cert_length+1];
  char cacert[cacert_length+1];
  char issuer[issuer_length+1];

  if (!enif_get_string(env,argv[0],cert,cert_length+1,ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_string(env,argv[1],cacert,cacert_length+1,ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_string(env,argv[2],issuer,issuer_length+1,ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  ret = ocsp_check(cert, cacert, cacert);

  if (ret == 0) {
    return enif_make_atom(env,"good");
  } else if (ret == 1) {
    return enif_make_atom(env,"revoked");
  } else {
    return enif_make_atom(env,"error");
  }
}

static ErlNifFunc nif_funcs[] =
{
  {"nif_check_ocsperl", 3, erlang_ocsperl_check}
};

ERL_NIF_INIT(ocsperl, nif_funcs, NULL, NULL, NULL, NULL)
