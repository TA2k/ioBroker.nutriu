'use strict';

/*
 * Created with @iobroker/create-adapter v2.6.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const Json2iob = require('json2iob');
const qs = require('qs');

class Nutriu extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'nutriu',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.deviceArray = [];
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create({
      withCredentials: true,
      headers: {
        'user-agent':
          'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
      },
      timeout: 3 * 60 * 1000, //3min client timeout
    });
    this.updateInterval = null;
    this.session = {};
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState('info.connection', false, true);
    if (this.config.interval < 1) {
      this.log.info('Set interval to minimum 1');
      this.config.interval = 1;
    }
    if (this.config.interval > 2147483647) {
      this.log.info('Set interval to maximum 2147483647');
      this.config.interval = 2147483647;
    }
    if (!this.config.username) {
      this.log.error('Please set username in the instance settings');
      return;
    }
    const vTokenState = await this.getStateAsync('auth.vtoken');
    if (vTokenState && vTokenState.val) {
      this.vtoken = vTokenState.val;
    }
    const contextState = await this.getStateAsync('auth.context');
    if (contextState && contextState.val) {
      this.context = contextState.val;
    }
    this.subscribeStates('*');
    await this.login();
    if (!this.session.access_token) {
      this.log.error('No session found');
      return;
    }
    await this.getDeviceList();
    this.updateInterval = setInterval(() => {
      this.updateDevices();
    }, this.config.interval * 1000);
  }
  async login() {
    if (!this.config.password) {
      this.log.info('No OTP found start OTP sending');
      await this.requestClient({
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://cdc.accounts.home.id/oidc/op/v1.0/4_JGZWlP8eQHpEqkvQElolbA/authorize',
        params: {
          client_id: '-u6aTznrxp9_9e_0a57CpvEG',
          code_challenge: 'e-X7435aOyHur7_mrjIiPNBk0vhOxQfrM-KmVE0jmqM',
          code_challenge_method: 'S256',
          nonce: 'jr3o3-vRNsFoLfb7LQlxHvConfik64BI_xaXZ6Bt0CQ',
          prompt: 'login',
          redirect_uri: 'com.philips.ka.oneka.app.prod://oauthredirect',
          response_type: 'code',
          scope:
            'openid profile email DI.Account.read DI.AccountProfile.read DI.AccountProfile.write DI.AccountGeneralConsent.read DI.AccountGeneralConsent.write DI.AccountSubscription.read DI.AccountSubscription.write DI.GeneralConsent.read DI.GeneralConsent.write VoiceProvider.read VoiceProvider.write offline_access subscriptions consents profile_extended',
          state: 'pDZ_UJai8noI9dhhWqspO7Uh8MIrhgdXGuYve5jiuiU',
          ui_locales: 'de-DE',
        },
        headers: {
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'sec-fetch-site': 'none',
          cookie:
            'glt_4_JGZWlP8eQHpEqkvQElolbA=st2.s.AtLtJAAJug.Upo-Xag8trt29nkkC2QlEyfWDNo6dH4jgrCcW-kOz4UN59EvaIeliz267LdlkoNrE9yJnXPSZ7XR09HzK4umNFxsiVUkU3SWnwIZUqbw2wteuFlVC7LZ3m7lz2ZCdj1c.xHw6E6lDOTJRHNhFg3fWdkpcqQ_GXWGV8JPEhFEL_Qb_Q3YeHiAxstY-ic3Br4p8p7HQwcyvjB2HjGhcXGuW7g.sc3',
          'sec-fetch-mode': 'navigate',
          'user-agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
          'accept-language': 'de-DE,de;q=0.9',
          'sec-fetch-dest': 'document',
        },
      })
        .then(async (res) => {
          //extract location header and save as state
          const location = res.request.res.responseUrl;
          this.log.debug('Location: ' + location);
          const context = location.split('context=')[1].split('&')[0];
          this.log.debug('Context: ' + context);
          await this.extendObjectAsync('auth.context', {
            type: 'state',
            common: {
              name: 'context',
              type: 'string',
              role: 'state',
              read: true,
              write: true,
            },
            native: {},
          });
          this.context = context;
          await this.setStateAsync('auth.context', { val: context, ack: true });
        })
        .catch((error) => {
          this.log.error('Error getting login page');
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
      await this.requestClient({
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://www.accounts.home.id/authui/client/proxy',
        params: {
          client_id: '-u6aTznrxp9_9e_0a57CpvEG',
          context: this.context,
          gig_ui_locales: 'de-DE',
          mode: 'forceLogin',
          prompt: 'login',
          scope:
            'openid profile email DI.Account.read DI.AccountProfile.read DI.AccountProfile.write DI.AccountGeneralConsent.read DI.AccountGeneralConsent.write DI.AccountSubscription.read DI.AccountSubscription.write DI.GeneralConsent.read subscriptions consents profile_extended',
        },
        headers: {
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'sec-fetch-site': 'none',
          cookie:
            'glt_4_JGZWlP8eQHpEqkvQElolbA=st2.s.AtLtJAAJug.Upo-Xag8trt29nkkC2QlEyfWDNo6dH4jgrCcW-kOz4UN59EvaIeliz267LdlkoNrE9yJnXPSZ7XR09HzK4umNFxsiVUkU3SWnwIZUqbw2wteuFlVC7LZ3m7lz2ZCdj1c.xHw6E6lDOTJRHNhFg3fWdkpcqQ_GXWGV8JPEhFEL_Qb_Q3YeHiAxstY-ic3Br4p8p7HQwcyvjB2HjGhcXGuW7g.sc3',
          'sec-fetch-mode': 'navigate',
          'user-agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
          'accept-language': 'de-DE,de;q=0.9',
          'sec-fetch-dest': 'document',
        },
      }).catch((error) => {
        this.log.error('Error getting login 1 page');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
      await this.requestClient({
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
        headers: {
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'sec-fetch-site': 'same-origin',
          cookie:
            'glt_4_JGZWlP8eQHpEqkvQElolbA=st2.s.AtLtJAAJug.Upo-Xag8trt29nkkC2QlEyfWDNo6dH4jgrCcW-kOz4UN59EvaIeliz267LdlkoNrE9yJnXPSZ7XR09HzK4umNFxsiVUkU3SWnwIZUqbw2wteuFlVC7LZ3m7lz2ZCdj1c.xHw6E6lDOTJRHNhFg3fWdkpcqQ_GXWGV8JPEhFEL_Qb_Q3YeHiAxstY-ic3Br4p8p7HQwcyvjB2HjGhcXGuW7g.sc3',
          referer:
            'https://www.accounts.home.id/authui/client/proxy?context=' +
            this.context +
            '&client_id=-u6aTznrxp9_9e_0a57CpvEG&mode=forceLogin&scope=openid+profile+email+DI.Account.read+DI.AccountProfile.read+DI.AccountProfile.write+DI.AccountGeneralConsent.read+DI.AccountGeneralConsent.write+DI.AccountSubscription.read+DI.AccountSubscription.write+DI.GeneralConsent.read+subscriptions+consents+profile_extended&prompt=login&gig_ui_locales=de-DE',
          'sec-fetch-dest': 'document',
          'sec-fetch-mode': 'navigate',
          'user-agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
          'accept-language': 'de-DE,de;q=0.9',
        },
      }).catch((error) => {
        this.log.error('Error getting login 2 page');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
      await this.requestClient({
        method: 'post',
        maxBodyLength: Infinity,
        url: 'https://cdc.accounts.home.id/accounts.otp.sendCode',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: '*/*',
          'sec-fetch-site': 'same-site',
          'accept-language': 'de-DE,de;q=0.9',
          'sec-fetch-mode': 'cors',
          origin: 'https://www.accounts.home.id',
          'user-agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
          referer: 'https://www.accounts.home.id/',
          'sec-fetch-dest': 'empty',
          cookie:
            'gmid=gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3;gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
        },
        data: {
          email: this.config.username,
          lang: 'de',
          APIKey: '4_JGZWlP8eQHpEqkvQElolbA',
          sdk: 'js_latest',
          authMode: 'cookie',
          pageURL:
            'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
          sdkBuild: '15703',
          format: 'json',
        },
      })
        .then(async (res) => {
          if (res.data && res.data.vToken) {
            this.log.info('Please enter the OTP code in the instance settings');
            await this.extendObjectAsync('auth.vtoken', {
              type: 'state',
              common: {
                name: 'vToken',
                type: 'string',
                role: 'state',
                read: true,
                write: true,
              },
              native: {},
            });
            await this.setStateAsync('auth.vtoken', { val: res.data.vToken, ack: true });
          } else {
            this.log.error('No vToken for OTP received');
            await this.setStateAsync('info.connection', false, true);
            await this.setStateAsync('auth.vtoken', { val: '', ack: true });
          }
        })
        .catch((error) => {
          this.log.error('Error sending OTP code');
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
    } else {
      this.log.info('OTP found start login');
      await this.requestClient({
        method: 'post',
        maxBodyLength: Infinity,
        url: 'https://cdc.accounts.home.id/accounts.otp.login',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: '*/*',
          'sec-fetch-site': 'same-site',
          'accept-language': 'de-DE,de;q=0.9',
          'sec-fetch-mode': 'cors',
          origin: 'https://www.accounts.home.id',
          'user-agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
          referer: 'https://www.accounts.home.id/',
          'sec-fetch-dest': 'empty',
          cookie:
            'gmid=gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3;gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
        },
        data: {
          vToken: this.vtoken,
          code: this.config.password,
          targetEnv: 'jssdk',
          includeUserInfo: 'true',
          include: 'profile,id_token,data,',
          sessionExpiration: '0',
          APIKey: '4_JGZWlP8eQHpEqkvQElolbA',
          sdk: 'js_latest',
          authMode: 'cookie',
          pageURL:
            'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
          sdkBuild: '15703',
          format: 'json',
        },
      })
        .then(async (res) => {
          if (res.data && res.data.errorMessage) {
            this.log.error('Login failed');
            this.log.error(res.data.errorMessage);

            await this.setStateAsync('info.connection', false, true);
            await this.setStateAsync('auth.vtoken', { val: '', ack: true });
            //get adapter config object
            const adapterConfig = 'system.adapter.' + this.name + '.' + this.instance;

            const obj = await this.getForeignObjectAsync(adapterConfig);
            if (obj.native && obj.native.password) {
              this.log.info('Delete incorrect OTP');
              obj.native.password = '';
              this.setForeignObject(adapterConfig, obj);
            }
            return;
          }
          this.log.debug(JSON.stringify(res.data));
          this.cdcsession = res.data;
        })
        .catch((error) => {
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });

      if (this.cdcsession) {
        await this.requestClient({
          method: 'post',
          maxBodyLength: Infinity,
          url: 'https://www.accounts.home.id/authui/api/ui/login',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/plain, */*',
            'sec-fetch-dest': 'empty',
            'sec-fetch-site': 'same-origin',
            'accept-language': 'de-DE,de;q=0.9',
            'sec-fetch-mode': 'cors',
            origin: 'https://www.accounts.home.id',
            'user-agent':
              'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            referer:
              'https://www.accounts.home.id/authui/client/login?client_id=-u6aTznrxp9_9e_0a57CpvEG&ui_locales=de-DE',
            'x-newrelic-id': 'undefined',
            cookie: 'glt_4_JGZWlP8eQHpEqkvQElolbA=' + this.cdcsession.sessionInfo.login_token,
          },
          data: { token: this.cdcsession.id_token },
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
          })
          .catch((error) => {
            this.log.error("Couldn't get session");
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        await this.requestClient({
          method: 'post',
          maxBodyLength: Infinity,
          url: 'https://cdc.accounts.home.id/oidc/op/v1.0/4_JGZWlP8eQHpEqkvQElolbA/contextData',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            accept: '*/*',
            'sec-fetch-site': 'same-site',
            'accept-language': 'de-DE,de;q=0.9',
            'sec-fetch-mode': 'cors',
            origin: 'https://www.accounts.home.id',
            'user-agent':
              'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            referer: 'https://www.accounts.home.id/',
            'sec-fetch-dest': 'empty',
            cookie:
              'glt_4_JGZWlP8eQHpEqkvQElolbA=' +
              this.cdcsession.sessionInfo.login_token +
              ';gmid=gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
          },
          data: {
            oidc_context: this.context,
            APIKey: '4_JGZWlP8eQHpEqkvQElolbA',
            sdk: 'js_latest',
            login_token: this.cdcsession.sessionInfo.login_token,
            authMode: 'cookie',
            pageURL:
              'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
            sdkBuild: '15703',
            format: 'json',
          },
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        const auth = await this.requestClient({
          method: 'get',
          maxBodyLength: Infinity,
          url: 'https://www.accounts.home.id/authui/api/ui/consent',
          params: {
            context: this.context,
            clientID: '-u6aTznrxp9_9e_0a57CpvEG',
            scope:
              'openid+profile+email+DI.Account.read+DI.AccountProfile.read+DI.AccountProfile.write+DI.AccountGeneralConsent.read+DI.AccountGeneralConsent.write+DI.AccountSubscription.read+DI.AccountSubscription.write+DI.GeneralConsent.read+subscriptions+consents+profile_extended',
            prompt: 'login',
            UID: this.cdcsession.UID,
            UIDSignature: this.cdcsession.UIDSignature,
            signatureTimestamp: this.cdcsession.signatureTimestamp,
          },
          headers: {
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'sec-fetch-site': 'same-origin',
            cookie:
              'glt_4_JGZWlP8eQHpEqkvQElolbA=' +
              this.cdcsession.sessionInfo.login_token +
              ';gmid=gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',

            'sec-fetch-dest': 'document',
            'accept-language': 'de-DE,de;q=0.9',
            'sec-fetch-mode': 'navigate',
            'user-agent':
              'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            referer: 'https://www.accounts.home.id/authui/client/proxy?mode=afterLogin',
          },
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            // return location query parameter as json
            const location = res.request.res.responseUrl;
            this.log.debug('Location: ' + location);
            const query = location.split('?')[1];
            const queryObject = qs.parse(query);
            this.log.debug('Query: ' + JSON.stringify(queryObject));
            return queryObject;
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        if (!auth) {
          this.log.error('No auth object received');
          return;
        }
        const codeResponse = await this.requestClient({
          method: 'get',
          maxBodyLength: Infinity,
          url: 'https://cdc.accounts.home.id/oidc/op/v1.0/4_JGZWlP8eQHpEqkvQElolbA/authorize/continue',
          params: {
            context: this.context,
            login_token: this.cdcsession.sessionInfo.login_token,
            consent: auth.consent,
            sig: auth.sig,
            userKey: auth.userKey,
          },
          headers: {
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'sec-fetch-site': 'same-site',
            cookie:
              'glt_4_JGZWlP8eQHpEqkvQElolbA=' +
              this.cdcsession.sessionInfo.login_token +
              '; gmid=gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4; hasGmid=ver4; ucid=XWTJJFteIdHoKhEWg1SEnw',

            'sec-fetch-dest': 'document',
            'accept-language': 'de-DE,de;q=0.9',
            'sec-fetch-mode': 'navigate',
            'user-agent':
              'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            referer: 'https://www.accounts.home.id/',
          },
        })
          .then(async (res) => {
            this.log.error("Couldn't get session");
            const location = res.request.res.responseUrl;
            this.log.error(JSON.stringify(qs.parse(location.split('?')[1])));
            // res.data && this.log.error(JSON.stringify(res.data));
          })
          .catch((error) => {
            if (error && error.message.includes('Unsupported protocol')) {
              return qs.parse(error.request._options.path.split('?')[1]);
            }
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        await this.requestClient({
          method: 'post',
          maxBodyLength: Infinity,
          url: 'https://cdc.accounts.home.id/oidc/op/v1.0/4_JGZWlP8eQHpEqkvQElolbA/token',
          headers: {
            accept: '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'user-agent': 'NutriU/1 CFNetwork/1410.0.3 Darwin/22.6.0',
            'accept-language': 'de-DE,de;q=0.9',
          },
          data: {
            client_id: '-u6aTznrxp9_9e_0a57CpvEG',
            code: codeResponse.code,
            code_verifier: 'hEEeOVX1XVL9YGPZXkm7XZroUyE00mT3B4DvBzt_Yk4',
            grant_type: 'authorization_code',
            redirect_uri: 'com.philips.ka.oneka.app.prod://oauthredirect',
          },
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            this.session = res.data;
            this.log.info('Login successful');
            await this.setStateAsync('info.connection', true, true);
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async getDeviceList() {
    this.log.info(`Getting devices`);
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url:
        'https://www.backend.vbs.versuni.com/api/0921897c-a457-443b-b555-5bbc7cd62985/Profile/self/Appliance?page=1&size=10&ts=' +
        Date.now(),
      headers: {
        accept: 'application/vnd.oneka.v2.0+json',
        authorization: 'Bearer ' + this.session.access_token,
        'x-user-agent': 'iOS 16.7.3;7.28.1',
        'user-agent': 'NutriU/7.28.1 (com.philips.cl.nutriu; build:1; iOS 16.7.3) Darwin/22.6.0 CFNetwork/1410.0.3',
        'accept-language': 'de-DE',
      },
    })
      .then(async (res) => {
        this.setState('info.connection', true, true);
        this.log.debug(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async updateDevices() {
    await this.requestClient({
      method: 'get',
      url: 'http://',
      headers: {
        'Content-Type': 'application/json',
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
      })
      .catch((error) => {
        //check for socket hangup
        if (error.code === 'ECONNRESET') {
          this.log.info('Bridge is busy. Cannot handle more requests');
          return;
        }
        this.log.warn(error);
        error.response && this.log.warn(JSON.stringify(error.response.data));
      });
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  async onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        // const deviceId = id.split('.')[2];
        let command = id.split('.')[4];
        if (id.split('.')[3] !== 'remote') {
          return;
        }

        if (command === 'refresh') {
          this.updateDevices();
          return;
        }
        if (state.val === false && command === 'lock') {
          command = 'unlock';
        }
        let mode;
        if (command === 'unlock') {
          mode = state.val || 0;
        }
        const url = 'http://';
        this.log.debug('Sending url: ' + url);
        await this.requestClient({
          method: 'POST',
          url: url,
          headers: {
            mode: mode || '',
          },
        })
          .then(async (res) => {
            this.log.info(JSON.stringify(res.data));
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      } else {
        if (id.split('.')[3] === 'state') {
          const deviceId = id.split('.')[2];
          if (state.val === 2 || state.val === 7 || state.val === 18) {
            this.setState(deviceId + '.remote.lock', false, true);
          }
          if (state.val === 7) {
            this.setState(deviceId + '.remote.pull', true, true);
          }
          if (state.val === 6) {
            this.setState(deviceId + '.remote.lock', true, true);
            this.setState(deviceId + '.remote.pull', false, true);
          }
        }
      }
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.refreshTimeout = setTimeout(() => {
        this.updateDevices();
      }, 10 * 1000);
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Nutriu(options);
} else {
  // otherwise start the instance directly
  new Nutriu();
}
