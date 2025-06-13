import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { Aab } from '../../src/android/Aab';
import { AndroidCodeUtils } from '../../src/android/utils/AndroidCodeUtils';

describe('Aab', () => {
  describe('getDexMapping', () => {
    it('Test getDexMapping with valid AAB', async () => {
      const aabBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn.aab'));
      const aab = await new Aab(aabBuffer);

      const dexMapping = await aab.getDexMapping();
      assert.notEqual(dexMapping, undefined);
    });

    it('Parses valid AAB class definitions and deobfuscates with DexMapping', async () => {
      const aabBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'obfuscated.aab'));
      const aab = await new Aab(aabBuffer);

      const dexMapping = await aab.getDexMapping();
      assert.notEqual(dexMapping, undefined);

      const classDefs = await aab.getClassDefinitions();

      // Intentionally reversed order for testing
      classDefs.sort((a, b) => b.signature.localeCompare(a.signature));

      const classDef0 = classDefs[0];
      assert.strictEqual(classDef0.signature, 'Lz0/e;');
      assert.strictEqual(
        dexMapping!.deobfuscate(AndroidCodeUtils.classSignatureToFqn(classDef0.signature)),
        'com.google.android.material.appbar.ViewOffsetHelper',
      );

      const classDef1 = classDefs[1];
      assert.strictEqual(classDef1.signature, 'Lz0/d;');
      assert.strictEqual(
        dexMapping!.deobfuscate(AndroidCodeUtils.classSignatureToFqn(classDef1.signature)),
        'com.google.android.material.appbar.ViewOffsetBehavior',
      );

      const classDef2 = classDefs[2];
      assert.strictEqual(classDef2.signature, 'Lz0/c;');
      assert.strictEqual(
        dexMapping!.deobfuscate(AndroidCodeUtils.classSignatureToFqn(classDef2.signature)),
        'com.google.android.material.appbar.HeaderScrollingViewBehavior',
      );

      // Contains an L
      const classDef1345 = classDefs[1345];
      assert.strictEqual(
        classDef1345.signature,
        'Landroidx/activity/OnBackPressedDispatcher$LifecycleOnBackPressedCancellable;',
      );
    });
  });

  describe('getClassDefinitions', () => {
    it('Parses valid AAB class definitions', async () => {
      const aabBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn.aab'));

      const aab = await new Aab(aabBuffer);
      const classDefinitions = await aab.getClassDefinitions();

      assert.strictEqual(classDefinitions.length, 4659);
    });
  });

  describe('getManifest', () => {
    it('Parses valid AAB manifest', async () => {
      const aabBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn.aab'));

      const aab = await new Aab(aabBuffer);
      const manifest = await aab.getManifest();

      assert.strictEqual(manifest.versionCode, '13');
      assert.strictEqual(manifest.versionName, '1.0.2');
      assert.strictEqual(manifest.application?.label, 'Hacker News');
      assert.strictEqual(manifest.application?.iconPath, 'res/mipmap-anydpi-v26/ic_launcher.xml');
      assert.strictEqual(manifest.packageName, 'com.emergetools.hackernews');
    });
  });

  describe('getSignatureIdentifier', () => {
    it('Always returns undefined for AAB signature identifier', async () => {
      const aabBuffer = fs.readFileSync(path.resolve('test', 'android', 'testAssets', 'hn.aab'));

      const aab = await new Aab(aabBuffer);
      const identifier = await aab.getSignatureIdentifier();

      assert.strictEqual(identifier, undefined);
    });
  });
});
