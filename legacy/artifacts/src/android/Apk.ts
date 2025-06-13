/* eslint-disable no-underscore-dangle */

import { AndroidArtifact, Artifact } from '../Artifact';
import { DexFileParser } from '../parsers/dex/DexFileParser';
import { ClassDefinition } from '../parsers/dex/DexFileParserTypes';
import { DexMapping } from '../parsers/dex/DexMapping';
import { AndroidSignatureParser } from '../parsers/signature/AndroidSignatureParser';
import { ZipProvider } from '../providers/ZipProvider';
import { AndroidManifest } from './manifest/AndroidManifest';
import { BinaryXmlUtils } from './manifest/axml/BinaryXmlUtils';
import { BinaryResourceTable } from './resources/binary/BinaryResourceTable';

export class Apk extends Artifact implements AndroidArtifact {
  zipProvider: ZipProvider;

  private _classDefinitions: ClassDefinition[] | undefined;

  private _manifest: AndroidManifest | undefined;

  private _resourceTables: BinaryResourceTable[] | undefined;

  constructor(content: Uint8Array) {
    super(content);
    this.zipProvider = new ZipProvider(content);
  }

  async getDexMapping(): Promise<DexMapping | undefined> {
    // Not packaged in APKs
    return undefined;
  }

  async getClassDefinitions(): Promise<ClassDefinition[]> {
    if (this._classDefinitions) {
      return this._classDefinitions;
    }

    const zip = await this.zipProvider.zip();
    const dexFiles = zip.file(/^[^\/]*\.dex$/);
    const dexBuffers = await Promise.all(dexFiles.map((file) => file.async('nodebuffer')));

    const classDefs = dexBuffers.flatMap((dexFileBuffer) => {
      const dexParser = new DexFileParser(dexFileBuffer, false);
      return dexParser.parseClassDefinitions();
    });
    this._classDefinitions = classDefs;
    return classDefs;
  }

  async getManifest(): Promise<AndroidManifest> {
    if (this._manifest) {
      return this._manifest;
    }

    const zip = await this.zipProvider.zip();
    const apkManifestFiles = zip.file(/^.*AndroidManifest\.xml$/);
    if (apkManifestFiles.length > 1) {
      throw new Error('Multiple AndroidManifest.xml files found in APK');
    }

    const manifestFile = apkManifestFiles.pop();
    if (!manifestFile) {
      throw new Error('Could not find manifest in APK');
    }

    const manifestBuffer = await manifestFile.async('nodebuffer');

    const binaryResTables = await this.getResourceTables();

    const manifest = await BinaryXmlUtils.binaryXmlToAndroidManifest(manifestBuffer, binaryResTables);
    this._manifest = manifest;
    return manifest;
  }

  async getResourceTables(): Promise<BinaryResourceTable[]> {
    if (this._resourceTables) {
      return this._resourceTables;
    }

    const zip = await this.zipProvider.zip();
    const arscFiles = zip.file(/^.*resources\.arsc$/);
    if (arscFiles.length > 1) {
      throw new Error('Multiple resources.arsc files found in APK');
    }

    const arscBuffer = await arscFiles.pop()?.async('nodebuffer');

    const binaryResTables = [];
    if (arscBuffer) {
      binaryResTables.push(new BinaryResourceTable(arscBuffer));
    }
    this._resourceTables = binaryResTables;
    return binaryResTables;
  }

  async getSignatureIdentifier(): Promise<string | undefined> {
    // TODO: Support Uint8Array
    const signature = new AndroidSignatureParser(this.content as Buffer);
    return signature.firstDigest();
  }
}
