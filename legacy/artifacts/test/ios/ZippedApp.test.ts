import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ZippedApp } from '../../src/ios/ZippedApp';

describe('ZippedApp', () => {
  describe('getAppPlist', () => {
    it('Test getAppPlist with valid app', async () => {
      const zippedAppBuffer = fs.readFileSync(path.resolve('test', 'ios', 'testAssets', 'hn.app.zip'));
      const zippedApp = new ZippedApp(zippedAppBuffer);

      const plist = await zippedApp.getAppPlist();

      assert.strictEqual(plist.CFBundleName, 'HackerNews');
      assert.strictEqual(plist.CFBundleIdentifier, 'com.emergetools.hackernews');
    });
  });

  describe('getBinaryUUID', () => {
    it('Test getBinaryUUID with valid app', async () => {
      const zippedAppBuffer = fs.readFileSync(path.resolve('test', 'ios', 'testAssets', 'hn.app.zip'));
      const zippedApp = new ZippedApp(zippedAppBuffer);
      const binaryUUID = await zippedApp.getBinaryUUID();
      assert.strictEqual(binaryUUID, '9A32267C-7039-34FA-AE20-8BEAD9E81742');
    });
  });
});
