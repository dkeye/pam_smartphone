#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    int rv;
    const char *rp = "20";
    const char *user; // имя пользователя
    char *password; // вводимый пользователем пароль
    char password_promt[64]; // запрос на ввод пароля, показываемый приложением

    // структуры PAM
    struct pam_conv *conv; // функция диалога PAM
    struct pam_message msg; // сообщения диалога PAM
    struct pam_message *(msgp[1]) = {&msg};
    struct pam_response *resp; // ответ PAM

    rv = pam_get_user(pamh, &user, NULL);
    if (rv != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s", pam_strerror(pamh, rv));
        return PAM_USER_UNKNOWN;
    }

    rv = pam_get_item(pamh, PAM_AUTHTOK, (void *) &password);
    if (rv == PAM_SUCCESS && password) {
        password = strdup(password);
    } else {
        sprintf(password_promt, "Password: ");
        msg.msg_style = PAM_PROMPT_ECHO_OFF;
        msg.msg = password_promt;

        rv = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
        if (rv != PAM_SUCCESS) {
            rv = PAM_AUTHINFO_UNAVAIL;
            goto out;
        }

        if ((conv == NULL) || conv->conv == NULL) {
            rv = PAM_AUTHINFO_UNAVAIL;
            goto out;
        }

        rv = conv->conv(1, (const struct pam_message **) msgp, &resp, conv->appdata_ptr);
        if (rv != PAM_SUCCESS) {
            rv = PAM_AUTHINFO_UNAVAIL;
            goto out;
        }

        if ((resp == NULL) || (resp[0].resp == NULL)) {
            rv = PAM_AUTHINFO_UNAVAIL;
            goto out;
        }

        // запоминаем пароль и очищаем память ответа
        password = strdup(resp[0].resp);
        memset(resp[0].resp, 0, strlen(resp[0].resp));
        free(&resp[0]);
    }
    if (strcmp(password, rp) != 0) {
        rv = PAM_AUTHINFO_UNAVAIL;
        goto out;
    }
    rv = PAM_SUCCESS;
    out:
    return rv;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {

    return PAM_SUCCESS;
}