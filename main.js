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
const { mqtt, iot } = require('aws-iot-device-sdk-v2');
const uuidv4 = require('uuid').v4;
const crypto = require('crypto');
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
    this.localDevices = {};
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
    this.homeSession = {};
    this.cdcsession = {};
    this.gmid =
      'gmid.ver4.AtLt4vuD2A.2v1uNAnlxTyjUtsN8UWiFgkri68y4UU5ZII52-mAQdqNYNDBbrgYcBhkinLfQMpc.aLgA8GZEYT_KSggB6YlYrpdq4kZU5D33jHhd-SysjaDGed_7c4uEW3HOJLPJo_CS9ApzFtQRz3_YTDIraIJosA.sc3';
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
    const uidState = await this.getStateAsync('auth.uid');
    if (uidState && uidState.val) {
      this.uid = uidState.val;
    }
    const homesessionState = await this.getStateAsync('auth.homesession');
    if (homesessionState && homesessionState.val) {
      this.homeSession = JSON.parse(homesessionState.val);
    }

    this.subscribeStates('*');
    if (this.homeSession.access_token) {
      await this.refreshToken();
      await this.getConsumerLogin();
    } else {
      await this.login();
    }
    if (!this.session.token) {
      this.log.error('No session found');
      return;
    }
    await this.getDeviceList();
    await this.getDeviceDetails();
    await this.updateLocalStatus();
    await this.connectMqtt();
    this.updateInterval = setInterval(() => {
      this.updateLocalStatus();
    }, 5 * 1000);
    this.refreshInterval = setInterval(async () => {
      await this.refreshToken();
      await this.getConsumerLogin();
      this.connectMqtt();
    }, 59 * 60 * 1000);
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
          cookie: 'gmid=' + this.gmid + ';gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
        },
        data: {
          email: this.config.username,
          lang: 'de',
          APIKey: '4_JGZWlP8eQHpEqkvQElolbA',
          sdk: 'js_latest',
          authMode: 'cookie',
          pageURL: 'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
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
          cookie: 'gmid=' + this.gmid + ';gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
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
          pageURL: 'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
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
            if (obj && obj.native && obj.native.password) {
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

      if (this.cdcsession.id_token) {
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
            referer: 'https://www.accounts.home.id/authui/client/login?client_id=-u6aTznrxp9_9e_0a57CpvEG&ui_locales=de-DE',
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
              ';gmid=' +
              this.gmid +
              '; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',
          },
          data: {
            oidc_context: this.context,
            APIKey: '4_JGZWlP8eQHpEqkvQElolbA',
            sdk: 'js_latest',
            login_token: this.cdcsession.sessionInfo.login_token,
            authMode: 'cookie',
            pageURL: 'https://www.accounts.home.id/authui/client/login?gig_ui_locales=de-DE&gig_client_id=-u6aTznrxp9_9e_0a57CpvEG&country=de',
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
              ';gmid=' +
              this.gmid +
              '; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4;hasGmid=ver4;ucid=XWTJJFteIdHoKhEWg1SEnw',

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
              '; gmid=' +
              this.gmid +
              '; gig_bootstrap_4_JGZWlP8eQHpEqkvQElolbA=cdc_ver4; hasGmid=ver4; ucid=XWTJJFteIdHoKhEWg1SEnw',

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
            this.homeSession = res.data;
            this.log.info('Login #1 successful');
            await this.extendObjectAsync('auth.homesession', {
              type: 'state',
              common: {
                name: 'homesession',
                type: 'string',
                role: 'state',
                read: true,
                write: true,
              },
              native: {},
            });
            await this.setStateAsync('auth.homesession', { val: JSON.stringify(res.data), ack: true });
            await this.extendObjectAsync('auth.uid', {
              type: 'state',
              common: {
                name: 'uid',
                type: 'string',
                role: 'state',
                read: true,
                write: true,
              },
              native: {},
            });
            await this.setStateAsync('auth.uid', { val: this.cdcsession.UID, ack: true });
            this.uid = this.cdcsession.UID;
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        if (this.homeSession.access_token) {
          await this.getConsumerLogin();
        }
      }
    }
  }

  async getConsumerLogin() {
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://www.backend.vbs.versuni.com/api/v2/auth/Consumer$login?requestLocation=onboarding',
      headers: {
        accept: '*/*',
        'content-type': 'application/json',
        'api-version': '2.0.0',
        'x-user-agent': 'iOS 16.7.2;7.28.1',
        'user-agent': 'NutriU/7.28.1 (com.philips.cl.nutriu; build:1; iOS 16.7.2) Darwin/22.6.0 CFNetwork/1410.0.3',
        'accept-language': 'de-DE',
      },
      data: {
        data: {
          type: 'consumerLoginRequest',
          attributes: {
            identityProvider: 'DI',
            name: this.config.username.split('@')[0],
            // guestProfileId: 'd1ba2056-c03e-49f1-95e2-c3e30f77214e',
            countryCode: 'DE',
            token: this.homeSession.access_token,
            email: this.config.username,
            userUUID: this.uid,
            spaceId: '76ad924e-982c-436e-a3b1-57dc71f73ca2',
          },
        },
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data && res.data.data && res.data.data.attributes) {
          this.session = res.data.data.attributes;
          this.log.debug('consumer Login successful');
          await this.setStateAsync('info.connection', true, true);
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async sasExchange() {
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://www.backend.vbs.versuni.com/api/sas/Token$exchange',
      headers: {
        accept: 'application/vnd.oneka.v2.0+json',
        'content-type': 'application/vnd.oneka.v2.0+json',
        'user-agent': 'NutriU/1 CFNetwork/1410.0.3 Darwin/22.6.0',
        'accept-language': 'de-DE,de;q=0.9',
        authorization: 'Bearer ' + this.homeSession.access_token,
      },
      data: {
        exchangeFor: 'HSDP',
        idToken: this.homeSession.id_token,
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.sasSession = res.data;
      })
      .catch(async (error) => {
        this.log.debug("SAS Exchange token didn't work");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://iam-service.eu-west.philips-healthsuite.com/authorize/oauth2/introspect',
      headers: {
        Host: 'iam-service.eu-west.philips-healthsuite.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'User-Agent': 'NutriU/1 CFNetwork/1410.0.3 Darwin/22.6.0',
        'api-version': '3',
        Connection: 'keep-alive',
        Accept: '*/*',
        'Accept-Language': 'de-DE,de;q=0.9',
        Authorization: 'Basic MjFlNDMxMTMxY2IwNGEwZWI1NjpAQDNmMi42bG8yMV8yRjYx',
      },
      data: { token: this.sasSession.accessToken },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.sas = res.data;
      })
      .catch(async (error) => {
        this.log.debug("SAS token didn't work");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async connectMqtt() {
    this.log.debug('Connect MQTT');
    if (this.mqttc) {
      await this.mqttc.disconnect().catch((error) => {
        this.log.debug('MQTT disconnect error: ' + error);
      });
    }
    await this.sasExchange();

    const config_builder = iot.AwsIotMqttConnectionConfigBuilder.new_default_builder();
    config_builder.with_clean_session(false);
    config_builder.with_client_id(this.sas.sub);
    config_builder.with_endpoint('iotgw.eu01.iot.hsdp.io');
    //config_builder.with_reconnect_max_sec(1000);
    //config_builder.with_reconnect_min_sec(10000);
    //config_builder.with_keep_alive_seconds(30);
    config_builder.with_custom_authorizer('foo', null, this.sasSession.signedToken, null, 'AuthorizationToken', this.sasSession.accessToken);
    const config = config_builder.build();
    const client = new mqtt.MqttClient();
    this.mqttc = client.new_connection(config);

    this.mqttc.on('connect', () => {
      if (!this.mqttc) return;
      this.log.debug('mqtt connected');
      this.mqttc.subscribe('prod/crl/things/' + this.sas.sub + '/cmd/receive/notified', mqtt.QoS.AtLeastOnce).catch((error) => {
        this.log.error('MQTT subscribe error: ' + error);
      });
      this.mqttc.subscribe('prod/crl/things/' + this.sas.sub + '/cmd/receive/accepted', mqtt.QoS.AtLeastOnce);
      this.mqttc.subscribe('prod/crl/things/' + this.sas.sub + '/cmd/receive/rejected', mqtt.QoS.AtLeastOnce);
      for (const device of this.deviceArray) {
        this.mqttc.publish(
          'prod/crl/things/' + device.externalDeviceId + '/cmd',
          JSON.stringify({
            cmdName: uuidv4(),
            cmdDetail: { op: 'Subscribe', ttl: 300, condorVersion: '1', path: '0/firmware' },
            updateNotifyRequired: true,
            timeToLive: 30,
          }),
          mqtt.QoS.AtLeastOnce
        );
        this.mqttc.publish(
          'prod/crl/things/' + device.externalDeviceId + '/cmd',
          JSON.stringify({
            cmdName: uuidv4(),
            cmdDetail: { op: 'Subscribe', condorVersion: '1', path: '1/airfryer', ttl: 300 },
            updateNotifyRequired: true,
            timeToLive: 30,
          }),
          mqtt.QoS.AtLeastOnce
        );
        this.mqttc.publish(
          'prod/crl/things/' + device.externalDeviceId + '/cmd',
          JSON.stringify({
            cmdName: uuidv4(),
            cmdDetail: { op: 'GetProps', condorVersion: '1', path: '1/airfryer', ttl: 300 },
            updateNotifyRequired: true,
            timeToLive: 30,
          }),
          mqtt.QoS.AtLeastOnce
        );
        this.mqttc.publish(
          'prod/crl/things/' + device.externalDeviceId + '/cmd',
          JSON.stringify({
            cmdName: uuidv4(),
            cmdDetail: { condorVersion: '1', values: { status: 'idle' }, op: 'PutProps', path: '1/airfryer' },
            updateNotifyRequired: true,
            timeToLive: 30,
          }),
          mqtt.QoS.AtLeastOnce
        );
        // this.mqttc.publish(
        //   'prod/crl/things/' + device.externalDeviceId + '/cmd',
        //   JSON.stringify({
        //     cmdName: uuidv4(),
        //     cmdDetail: { op: 'Subscribe', condorVersion: '1', path: '1/machinestatus', ttl: 300 },
        //     updateNotifyRequired: true,
        //     timeToLive: 30,
        //   }),
        //   mqtt.QoS.AtLeastOnce
        // );
        // this.mqttc.publish(
        //   'prod/crl/things/' + device.externalDeviceId + '/cmd',
        //   JSON.stringify({
        //     cmdName: uuidv4(),
        //     cmdDetail: { op: 'Subscribe', condorVersion: '1', path: '1/hermesac', ttl: 300 },
        //     updateNotifyRequired: true,
        //     timeToLive: 30,
        //   }),
        //   mqtt.QoS.AtLeastOnce
        // );
        // this.mqttc.publish(
        //   'prod/crl/things/' + device.externalDeviceId + '/cmd',
        //   JSON.stringify({
        //     cmdName: uuidv4(),
        //     cmdDetail: { op: 'Subscribe', condorVersion: '1', path: '1/nutrimax', ttl: 300 },
        //     updateNotifyRequired: true,
        //     timeToLive: 30,
        //   }),
        //   mqtt.QoS.AtLeastOnce
        // );
      }
    });

    this.mqttc.on('message', (topic, payload) => {
      try {
        if (!this.firstMessageReceived) {
          this.firstMessageReceived = true;
          this.log.info('First MQTT message received');
        }
        const json = Buffer.from(payload);
        const data = JSON.parse(json.toString('utf-8'));
        this.log.debug(`Message MQTT: ${JSON.stringify(data)}`);
        if (data.type !== 'accepted') {
          if (data.command && data.command.statusDetail) {
            const deviceId = data.topic.split('/')[3];
            this.json2iob.parse(deviceId + '.' + data.command.statusDetail.op.toLowerCase(), data.command.statusDetail, {
              channelName: 'response from device',
            });
          }
        }
      } catch (error) {
        this.log.error(error);
      }
    });
    this.mqttc.on('error', (error) => {
      this.log.error('MQTT error: ' + error);
    });
    await this.mqttc.connect().catch((error) => {
      this.log.error('MQTT connect error: ' + error);
    });
  }

  async refreshToken() {
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
        grant_type: 'refresh_token',
        refresh_token: this.homeSession.refresh_token,
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.homeSession = res.data;
        await this.setStateAsync('auth.homesession', { val: JSON.stringify(res.data), ack: true });
      })
      .catch(async (error) => {
        this.log.debug("Refresh token didn't work");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.info('Delete all session infos');
        await this.setStateAsync('auth.vtoken', { val: '', ack: true });
        await this.setStateAsync('auth.context', { val: '', ack: true });
        await this.setStateAsync('auth.uid', { val: '', ack: true });
        await this.setStateAsync('auth.homesession', { val: '', ack: true });
        const obj = await this.getForeignObjectAsync('system.adapter.' + this.name + '.' + this.instance);
        if (obj && obj.native && obj.native.password) {
          this.log.info('Delete  OTP');
          obj.native.password = '';
          this.setForeignObject('system.adapter.' + this.name + '.' + this.instance, obj);
        }
      });
  }
  async getDeviceList() {
    this.log.info(`Getting devices`);
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://www.backend.vbs.versuni.com/api/0921897c-a457-443b-b555-5bbc7cd62985/Profile/self/Appliance?page=1&size=10&ts=' + Date.now(),
      headers: {
        accept: 'application/vnd.oneka.v2.0+json',
        authorization: 'Bearer ' + this.session.token,
        'x-user-agent': 'iOS 16.7.3;7.28.1',
        'user-agent': 'NutriU/7.28.1 (com.philips.cl.nutriu; build:1; iOS 16.7.3) Darwin/22.6.0 CFNetwork/1410.0.3',
        'accept-language': 'de-DE',
      },
    })
      .then(async (res) => {
        this.setState('info.connection', true, true);
        this.log.debug(JSON.stringify(res.data));
        if (res.data._embedded && res.data._embedded.item) {
          this.log.info('Found ' + res.data._embedded.item.length + ' devices');
          for (const device of res.data._embedded.item) {
            this.deviceArray.push(device);
            this.log.debug('Device: ' + JSON.stringify(device));
            const id = device.externalDeviceId;
            await this.extendObjectAsync(id, {
              type: 'device',
              common: {
                name: device.name,
                role: 'device',
              },
              native: device,
            });
            await this.extendObjectAsync(id + '.general', {
              type: 'channel',
              common: {
                name: 'General',
              },
              native: {},
            });
            this.json2iob.parse(id + '.general', device);
          }
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceDetails() {
    for (const device of this.deviceArray) {
      if (device._links.device) {
        const url = device._links.device.href.replace('{?country,unitSystem}', '?country=DE&unitSystem=METRIC');
        await this.requestClient({
          method: 'get',
          url: url,
          headers: {
            accept: 'application/vnd.oneka.v2.0+json',
            authorization: 'Bearer ' + this.session.token,
            'x-user-agent': 'iOS 16.7.3;7.28.1',
            'user-agent': 'NutriU/7.28.1 (com.philips.cl.nutriu; build:1; iOS 16.7.3) Darwin/22.6.0 CFNetwork/1410.0.3',
            'accept-language': 'de-DE',
          },
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            this.json2iob.parse(device.externalDeviceId + '.details', res.data, { channelName: 'details of device' });
            if (res.data._links && res.data._links.deviceNetworkConfigs) {
              await this.requestClient({
                method: 'get',
                url: res.data._links.deviceNetworkConfigs.href,
                headers: {
                  accept: 'application/vnd.oneka.v2.0+json',
                  authorization: 'Bearer ' + this.session.token,
                  'x-user-agent': 'iOS 16.7.3;7.28.1',
                  'user-agent': 'NutriU/7.28.1 (com.philips.cl.nutriu; build:1; iOS 16.7.3) Darwin/22.6.0 CFNetwork/1410.0.3',
                  'accept-language': 'de-DE',
                },
              })
                .then(async (res) => {
                  this.log.debug(JSON.stringify(res.data));
                  for (const network of res.data._embedded.item) {
                    if (network.ipAddress) {
                      device.ipAdress = network.ipAddress;
                    }
                  }
                  this.json2iob.parse(device.externalDeviceId + '.network', res.data, { channelName: 'network information' });
                })
                .catch((error) => {
                  this.log.error(error);
                  error.response && this.log.error(JSON.stringify(error.response.data));
                });
            }
          })
          .catch((error) => {
            this.log.warn(error);
            error.response && this.log.warn(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async updateLocalStatus() {
    for (const device of this.deviceArray) {
      if (device.ipAddress) {
        const headers = { 'User-Agent': 'cml', 'Content-Type': 'application/json' };
        if (device.token) {
          headers.authorization = 'PHILIPS-Condor ' + device.token;
        }
        await this.requestClient({
          method: 'get',
          url: 'http://' + device.ipAddress + '/di/v1/products/1/airfryer',
          headers: headers,
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            this.json2iob.parse(device.externalDeviceId + '.status', res.data, { channelName: 'local status' });
          })
          .catch(async (error) => {
            if (error.response && error.response.status === 401) {
              this.log.debug('Token expired');
              const challange = error.response.headers['www-authenticate'].replace('PHILIPS-Condor ', '');
              await this.getLocalAuth(device, challange);
              await this.updateLocalStatus();
            }
            this.log.warn(error);
            error.response && this.log.warn(JSON.stringify(error.response.data));
          });
      }
    }
  }
  async getLocalAuth(device, challange) {
    const vvv =
      Buffer.from(challange, 'base64').toString('utf-8') +
      Buffer.from(device.clientId, 'base64').toString('utf-8') +
      Buffer.from(device.clientSecret, 'base64').toString('utf-8');
    const myhash = crypto.createHash('sha256').update(vvv).digest('hex');
    const myhashhex = Buffer.from(myhash, 'hex');
    const res = Buffer.concat([Buffer.from(device.clientId, 'base64'), myhashhex]);
    const encoded = res.toString('base64');
    device.token = encoded;
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  async onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.mqttc && this.mqttc.disconnect().catch((error) => this.log.debug('MQTT disconnect error: ' + error));
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
          this.getDeviceDetails();
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
        this.refreshTimeout && clearTimeout(this.refreshTimeout);
        this.refreshTimeout = setTimeout(() => {
          this.getDeviceDetails();
        }, 10 * 1000);
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
