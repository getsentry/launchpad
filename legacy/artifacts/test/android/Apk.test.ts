import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { Apk } from '../../src/android/Apk';

describe('Apk', () => {
  describe('getDexMapping', () => {
    it('Test getDexMapping from apk always undefined', async () => {
      const apkBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn_universal.apk'));

      const apk = await new Apk(apkBuffer);

      const dexMapping = await apk.getDexMapping();
      assert.strictEqual(dexMapping, undefined);
    });
  });

  describe('getClassDefinitions', () => {
    it('Parses valid APK class definitions', async () => {
      const apkBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn_universal.apk'));

      const apk = await new Apk(apkBuffer);
      const classDefinitions = await apk.getClassDefinitions();

      assert.strictEqual(classDefinitions.length, 4610);
    });
  });

  describe('getManifest', () => {
    it('Parses valid APK manifest', async () => {
      const apkBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn_universal.apk'));

      const apk = await new Apk(apkBuffer);
      const manifest = await apk.getManifest();

      assert.strictEqual(manifest.versionCode, '10');
      assert.strictEqual(manifest.versionName, '1.0.1');
      assert.strictEqual(manifest.application?.label, 'Hacker News');
      assert.strictEqual(manifest.application?.iconPath, 'res/mipmap-anydpi-v26/ic_launcher.xml');
      assert.strictEqual(manifest.packageName, 'com.emergetools.hackernews');
    });
  });

  describe('getSignatureIdentifier', () => {
    it('Parses valid APK signature and returns identifier', async () => {
      const apkBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn_universal.apk'));

      const apk = await new Apk(apkBuffer);
      const identifier = await apk.getSignatureIdentifier();

      assert.strictEqual(identifier, 'tQFIbBAaBZg2IXguwMnurpEwevyF7/2W+LEVXoXX7hc=');
    });
  });
});
