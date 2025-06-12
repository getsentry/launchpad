/* eslint-disable no-underscore-dangle */

import { Artifact, IOSArtifact } from '../Artifact';
import { MachOParser } from '../parsers/macho/MachOParser';
import { ZipProvider } from '../providers/ZipProvider';
import { PlistUtils } from './utils/PlistUtils';

export class ZippedApp extends Artifact implements IOSArtifact {
  zipProvider: ZipProvider;

  _plistJson: any | undefined;

  constructor(content: Uint8Array) {
    super(content);
    this.zipProvider = new ZipProvider(content);
  }

  async getMacosAppPlist(): Promise<any | undefined> {
    // .app has no macOS plist
    return undefined;
  }

  async plist(): Promise<any> {
    if (this._plistJson) {
      return this._plistJson;
    }

    const zip = await this.zipProvider.zip();

    const appPlistFile = zip.file(/^[^\/]*\.app\/(Contents\/)?Info\.plist$/)[0];
    if (!appPlistFile) {
      throw Error('Could not find plist in root of .app.');
    }

    const plistBuffer = await appPlistFile.async('nodebuffer');
    const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
    if (!plistJson) {
      throw Error(`Error processing plist: ${appPlistFile.name}`);
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

    if (plist.CFBundleIdentifier) {
      return plist;
    }

    const zip = await this.zipProvider.zip();
    const nestedPlists = zip.file(/.*\.app\/Info\.plist/);
    // Sort by length to try with the shortest ones first
    nestedPlists.sort((a, b) => a.name.length - b.name.length);

    for (const nestedPlist of nestedPlists) {
      const plistBuffer = await nestedPlist.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);
      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find bundle plist for .app');
  }

  async getWatchAppPlist(): Promise<any | undefined> {
    const zip = await this.zipProvider.zip();
    const watchPlistFiles = zip.file(/Watch\/.*\.app\/Info\.plist/);

    for (const plistFile of watchPlistFiles) {
      const plistBuffer = await plistFile.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);

      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find Watch App plist in .app');
  }

  async getAppClipPlist(): Promise<any | undefined> {
    const zip = await this.zipProvider.zip();
    const appClipPlistFiles = zip.file(/AppClips\/.*\.app\/Info\.plist/);

    for (const plistFile of appClipPlistFiles) {
      const plistBuffer = await plistFile.async('nodebuffer');
      const plistJson = await PlistUtils.safelyParsePlist(plistBuffer);

      if (plistJson?.CFBundleIdentifier) {
        return plistJson;
      }
    }

    console.log('Could not find App Clip plist in xcarchive');
  }

  async getBinaryUUID(): Promise<string | undefined> {
    const executable = await this.getExecutable();
    if (!executable) {
      return undefined;
    }

    const parser = new MachOParser(executable);
    const loadCommands = parser.parseLoadCommands();

    for (const loadCommand of loadCommands) {
      if (loadCommand.name === 'LC_UUID') {
        return loadCommand.uuid;
      }
    }

    console.log('No LC_UUID found in Mach-O file');
    return undefined;
  }

  async getExecutable(): Promise<Buffer | undefined> {
    const plist = await this.getAppPlist();
    if (!plist) {
      console.log('Missing plist, could not find executable');
      return;
    }

    const executableName = plist.CFBundleExecutable;

    // Escape the executable name for regex
    const escapedExecutable = executableName.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');

    const zip = await this.zipProvider.zip();
    const executable = zip.file(new RegExp(`^[^\/]*.app\/(Contents\/MacOS\/)?${escapedExecutable}$`))[0];
    if (!executable) {
      return;
    }

    return executable.async('nodebuffer');
  }
}
