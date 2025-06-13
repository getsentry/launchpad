/* eslint-disable no-underscore-dangle */

import { Artifact, IOSArtifact } from '../Artifact';
import { NormalizedZipProvider } from '../providers/NormalizedZipProvider';
import { ZipProvider } from '../providers/ZipProvider';
import { PlistUtils } from './utils/PlistUtils';

export class ZippedXCFramework extends Artifact implements IOSArtifact {
  private zipProvider: ZipProvider;

  _plistJson: any | undefined;

  constructor(content: Uint8Array) {
    super(content);
    this.zipProvider = new NormalizedZipProvider(content);
  }

  async plist(): Promise<any> {
    if (this._plistJson) {
      return this._plistJson;
    }

    const zip = await this.zipProvider.zip();

    const frameworkPlistFile = zip.file(/^.*\.xcframework\/Info\.plist/)[0];
    if (!frameworkPlistFile) {
      throw Error('Could not find plist in root of xcframework.');
    }

    const plistBuffer = await frameworkPlistFile.async('nodebuffer');
    const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
    if (!plistJson) {
      throw Error(`Error processing plist: ${frameworkPlistFile.name}`);
    }

    this._plistJson = plistJson;
    return plistJson;
  }

  async getAppPlist(): Promise<any | undefined> {
    const plist = await this.plist();

    const topLevelAppId = plist.ApplicationProperties?.CFBundleIdentifier;
    if (topLevelAppId) {
      return plist;
    }

    const zip = await this.zipProvider.zip();
    const nestedPlists = zip.file(/.*\.framework\/Info\.plist$/);

    for (const nestedPlist of nestedPlists) {
      const plistBuffer = await nestedPlist.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find app plist for framework');
  }

  async getMacosAppPlist(): Promise<any | undefined> {
    // Not used with XCFrameworks
    return undefined;
  }

  async getWatchAppPlist(): Promise<any | undefined> {
    // Not used with XCFrameworks
    return undefined;
  }

  async getAppClipPlist(): Promise<any | undefined> {
    // Not used with XCFrameworks
    return undefined;
  }

  async getBinaryUUID(): Promise<string | undefined> {
    // Not used with XCFrameworks
    return undefined;
  }
}
