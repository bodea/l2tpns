#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

char const *l2tp_code(int type);
char const *l2tp_avp_name(int avp);
char const *l2tp_stopccn_result_code(int code);
char const *l2tp_cdn_result_code(int code);
char const *l2tp_error_code(int code);
char const *ppp_phase(int code);
char const *ppp_state(int code);
char const *ppp_auth_type(int type);
char const *ppp_code(int type);
char const *ppp_lcp_option(int type);
char const *radius_state(int state);
char const *radius_code(int code);

#endif /* __CONSTANTS_H__ */
