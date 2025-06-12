/* eslint-disable no-underscore-dangle */

import JSZip from 'jszip';
import path from 'path';
import { Artifact, IOSArtifact } from '../Artifact';
import { NormalizedZipProvider } from '../providers/NormalizedZipProvider';
import { ZipProvider } from '../providers/ZipProvider';
import { ZippedApp } from './ZippedApp';
import { PlistUtils } from './utils/PlistUtils';

/**
 * Zip file containing a single .xcarchive file.
 */
export class ZippedXCArchive extends Artifact implements IOSArtifact {
  protected zipProvider: ZipProvider;

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
    const xcarchiveMatches = zip.folder(/^[^\/]+\.xcarchive\/$/);
    // Some payloads have the xcarchive contents in a .xcarchive subdirectory, others have it at the top level
    const xcarchiveRoot = xcarchiveMatches[0] ? zip.folder(xcarchiveMatches[0].name) : zip;
    if (!xcarchiveRoot) {
      throw Error('Could not find xcarchive root.');
    }

    const archivePlistFile = xcarchiveRoot.file('Info.plist');
    if (!archivePlistFile) {
      throw Error('Could not find plist in root of xcarchive.');
    }

    const plistBuffer = await archivePlistFile.async('nodebuffer');
    const plistJson = PlistUtils.safelyParsePlist(plistBuffer);
    if (!plistJson) {
      throw Error(`Error processing plist: ${archivePlistFile.name}`);
    }

    this._plistJson = plistJson;
    return plistJson;
  }

  async getAppPlist(): Promise<any | undefined> {
    const plist = await this.plist();
    const zip = await this.zipProvider.zip();

    const applicationPath = plist.ApplicationProperties?.ApplicationPath;
    if (applicationPath) {
      const appPlist = zip.file(new RegExp(`${applicationPath}/Info\\.plist`));
      if (appPlist.length > 0) {
        const plistBuffer = await appPlist[0].async('nodebuffer');
        const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
        if (PlistUtils.isValidiOSPlist(plistJson)) {
          return plistJson;
        }
      }
    }

    const appFolderPath = await this.getAppFolderPath();
    const appPlist = zip.file(new RegExp(`${appFolderPath}\\/[^/]+\\.app\\/Info\\.plist$`));
    if (appPlist.length > 0) {
      const plistBuffer = await appPlist[0].async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
      if (PlistUtils.isValidiOSPlist(plistJson)) {
        return plistJson;
      }
    }

    const macosPlist = await this.getMacosAppPlist();
    if (macosPlist) {
      return null;
    }

    // Ideally should not hit this case, but some archives have the .app in a different subfolder
    const allPlists = zip.file(/.*\/Info\.plist/);
    const nestedPlists = allPlists.filter((file) => !file.name.includes('/dSYMs/'));
    for (const nestedPlist of nestedPlists) {
      const plistBuffer = await nestedPlist.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
      if (PlistUtils.isValidiOSPlist(plistJson)) {
        return plistJson;
      }
    }

    // This can sometimes have internal names, so check it last
    const topLevelAppId = plist.ApplicationProperties?.CFBundleIdentifier;
    if (topLevelAppId) {
      return plist;
    }

    console.log('Could not find plist for xcarchive');
  }

  async getMacosAppPlist(): Promise<any | undefined> {
    const zip = await this.zipProvider.zip();
    const appFolderPath = await this.getAppFolderPath();
    const appPlist = zip.file(new RegExp(`${appFolderPath}\\/[^/]+\\.app\\/Contents/Info\\.plist$`));
    if (appPlist.length > 0) {
      const plistBuffer = await appPlist[0].async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
      if (PlistUtils.isMacosPlist(plistJson)) {
        return plistJson;
      }
    }

    console.log('Could not find MacOS App plist in xcarchive');
  }

  async getWatchAppPlist(): Promise<any | undefined> {
    const zip = await this.zipProvider.zip();
    const appFolderPath = await this.getAppFolderPath();
    const watchPlistFiles = zip.file(
      new RegExp(`${appFolderPath}\\/[^/]+\\.app\\/Watch\\/[^/]+\\.app\\/Info\\.plist$`),
    );

    for (const plistFile of watchPlistFiles) {
      const plistBuffer = await plistFile.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);

      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find Watch App plist in xcarchive');
  }

  async getAppClipPlist(): Promise<any | undefined> {
    const zip = await this.zipProvider.zip();
    const appFolderPath = await this.getAppFolderPath();
    const appClipPlistFiles = zip.file(
      new RegExp(`${appFolderPath}\\/[^/]+\\.app\\/AppClips\\/[^/]+\\.app\\/Info\\.plist$`),
    );

    for (const plistFile of appClipPlistFiles) {
      const plistBuffer = await plistFile.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);

      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find App Clip plist in xcarchive');
  }

  private async getAppFolderPath(): Promise<string> {
    const plist = await this.plist();
    const applicationPath = plist.ApplicationProperties?.ApplicationPath;

    let appFolderPath: string;
    if (applicationPath) {
      appFolderPath = path.dirname(`Products/${applicationPath}`);
    } else {
      appFolderPath = 'Products/Applications';
    }

    return appFolderPath;
  }

  async hasAppFolder(): Promise<boolean> {
    const zip = await this.zipProvider.zip();
    const appFolderPath = this.getAppFolderPath();
    const appFolder = zip.folder(new RegExp(`${appFolderPath}/.*\.app`));
    return appFolder !== null && appFolder.length > 0;
  }

  async getBinaryUUID(): Promise<string | undefined> {
    const app = await this.getApp();
    if (!app) {
      return undefined;
    }

    return app.getBinaryUUID();
  }

  async getApp(): Promise<ZippedApp | undefined> {
    const hasAppFolder = await this.hasAppFolder();
    if (!hasAppFolder) {
      console.log(`No app in xcarchive`);
      return;
    }

    const appFolderPath = await this.getAppFolderPath();
    const zip = await this.zipProvider.zip();

    // Find all files in the app folder path - include the full path with the zip file's name
    const appFiles = zip.file(new RegExp(`.*${appFolderPath}/[^/]+\\.app/.*`));
    if (!appFiles || appFiles.length === 0) {
      console.log(`No app files found at path: ${appFolderPath}`);
      return;
    }

    // Create a new zip with all the app files
    const newZip = new JSZip();
    for (const file of appFiles) {
      const fileData = await file.async('uint8array');
      // Extract the app name and path after the app folder
      const appNameMatch = file.name.match(new RegExp(`.*${appFolderPath}/([^/]+\\.app/.*)`));
      if (appNameMatch && appNameMatch[1]) {
        const relativePath = appNameMatch[1];
        newZip.file(relativePath, fileData);
      }
    }

    const appZip = await newZip.generateAsync({ type: 'uint8array' });
    return new ZippedApp(appZip);
  }
}
