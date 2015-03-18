-module(mod_account).

-behaviour(gen_mod).

-include("ejabberd.hrl").
-include("jlib.hrl").

-export([start/2,
         stop/1,
         unauthenticated_iq/4]).

start(Host, Opts) ->
  ejabberd_hooks:add(c2s_unauthenticated_iq, Host,
                       ?MODULE, unauthenticated_iq, 10),
  ok.

stop(Host) ->
  ejabberd_hooks:delete(c2s_unauthenticated_iq, Host,
                          ?MODULE, unauthenticated_iq, 10).

unauthenticated_iq(_Acc, Server, #iq{type = Type, sub_el = SubEl, xmlns = ?NS_ACCOUNT} = IQ, _IP) ->
    io:format(" got unauthenticated IQ ~p ~n",[IQ]),
    case Type of
        set ->
           UT = xml:get_subtag(SubEl, <<"username">>),
           PT = xml:get_subtag(SubEl, <<"password">>),
           RT = xml:get_subtag(SubEl, <<"resource">>),
           if (UT /= false) and (PT /= false) and (RT /= false) ->
               User = xml:get_tag_cdata(UT),
               Password = xml:get_tag_cdata(PT),
               Resource = xml:get_tag_cdata(RT),
               case ejabberd_auth:check_password_with_authmodule(User, Server, Password) of
                 {true, AuthModule} ->
                    {c2s_auth, User, Resource, AuthModule};
                 false ->
                   unauthorized
               end;
             true ->
               unauthorized
           end;
        _ ->
           unauthorized
    end;

unauthenticated_iq(Acc, _Server, _IQ, _IP) ->
    Acc.

