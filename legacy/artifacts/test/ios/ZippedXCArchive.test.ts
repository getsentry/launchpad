import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ZippedXCArchive } from '../../src/ios/ZippedXCArchive';

describe('ZippedXCArchive', () => {
  describe('getAppPlist', () => {
    it('Test getAppPlist with valid xcarchive', async () => {
      const zippedXcarchiveBuffer = fs.readFileSync(path.resolve('test', 'ios', 'testAssets', 'hn.xcarchive.zip'));
      const zippedXCArchive = new ZippedXCArchive(zippedXcarchiveBuffer);

      const plist = await zippedXCArchive.getAppPlist();

      assert.strictEqual(plist.CFBundleName, 'HackerNews');
      assert.strictEqual(plist.CFBundleIdentifier, 'com.emergetools.hackernews');
    });
  });
});
