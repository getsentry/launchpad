import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ZippedXCFramework } from '../../src/ios/ZippedXCFramework';

describe('ZippedXCFramework', () => {
  describe('getAppPlist', () => {
    it('Test getAppPlist with valid xcframwork', async () => {
      const zippedXcframeworkBuffer = fs.readFileSync(
        path.resolve('test', 'ios', 'testAssets', 'Sentry.xcframework.zip'),
      );
      const zippedXCFramework = new ZippedXCFramework(zippedXcframeworkBuffer);

      const plist = await zippedXCFramework.getAppPlist();

      assert.strictEqual(plist.CFBundleName, 'Sentry');
      assert.strictEqual(plist.CFBundleIdentifier, 'io.sentry.Sentry');
    });
  });
});
