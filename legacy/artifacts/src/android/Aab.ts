/* eslint-disable no-underscore-dangle */

import { AndroidArtifact, Artifact } from '../Artifact';
import { DexFileParser } from '../parsers/dex/DexFileParser';
import { ClassDefinition } from '../parsers/dex/DexFileParserTypes';
import { DexMapping } from '../parsers/dex/DexMapping';
import { ZipProvider } from '../providers/ZipProvider';
import { AndroidManifest } from './manifest/AndroidManifest';
import { ProtoXmlUtils } from './manifest/proto/ProtoXmlUtils';
import { ProtobufResourceTable } from './resources/proto/ProtobufResourceTable';

export class Aab extends Artifact implements AndroidArtifact {
  protected zipProvider: ZipProvider;

  private _dexMapping: DexMapping | undefined;

  private _classDefinitions: ClassDefinition[] | undefined;

  private _manifest: AndroidManifest | undefined;

  private _resourceTables: ProtobufResourceTable[] | undefined;

  constructor(content: Uint8Array) {
    super(content);
    this.zipProvider = new ZipProvider(content);
  }

  async getDexMapping(): Promise<DexMapping | undefined> {
    if (this._dexMapping) {
      return this._dexMapping;
    }

    const zip = await this.zipProvider.zip();
    const dexMappingFiles = zip.file(
      /^(.*?\/?)(BUNDLE-METADATA\/com\.android\.tools\.build\.obfuscation)\/(proguard|mapping)(\.)(txt|pro|map)$/,
    );

    // Should only be one dex mapping file included in the AAB.
    const dexMappingFile = dexMappingFiles.pop();
    if (!dexMappingFile) {
      return;
    }

    const dexMappingBuffer = await dexMappingFile.async('nodebuffer');
    const dexMapping = DexMapping.parse(dexMappingBuffer);
    this._dexMapping = dexMapping;
    return dexMapping;
  }

  async getClassDefinitions(): Promise<ClassDefinition[]> {
    if (this._classDefinitions) {
      return this._classDefinitions;
    }

    const zip = await this.zipProvider.zip();
    // Only want dex files in dex directory, like /base/dex/*.dex.
    // Sometimes we've seen dex in other folders like /base/assets/*.dex which tend to be invalid.
    const dexFiles = zip.file(/^([^\/]+\/)dex\/[^\/]+\.dex$/);
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
    const baseManifestFile = zip.file(/^.*base\/manifest\/AndroidManifest\.xml$/).pop();
    if (!baseManifestFile) {
      throw new Error('Could not find manifest in base/manifest of AAB.');
    }

    const [manifestXmlArray, protoResTables] = await Promise.all([
      baseManifestFile.async('uint8array'),
      this.getResourceTables(),
    ]);

    const manifest = ProtoXmlUtils.xmlProtoToAndroidManifest(baseManifestFile.name, manifestXmlArray, protoResTables);
    this._manifest = manifest;
    return manifest;
  }

  async getResourceTables(): Promise<ProtobufResourceTable[]> {
    if (this._resourceTables) {
      return this._resourceTables;
    }

    const zip = await this.zipProvider.zip();
    const baseResourcesFile = zip.file(/^.*base\/resources\.pb$/).pop();
    if (!baseResourcesFile) {
      throw new Error(`Could not find resources.pb for ${zip.name}`);
    }
    const protoResTableBuffer = await baseResourcesFile.async('nodebuffer');
    const protoResTables = [new ProtobufResourceTable(protoResTableBuffer)];
    this._resourceTables = protoResTables;
    return protoResTables;
  }

  async getSignatureIdentifier(): Promise<string | undefined> {
    // AABs can create many APKs with different identifiers.
    return undefined;
  }
}
