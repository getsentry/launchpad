import { AndroidManifest } from './android/manifest/AndroidManifest';
import { ResourceTable } from './android/resources/ResourceTable';
import { ClassDefinition } from './parsers/dex/DexFileParserTypes';
import { DexMapping } from './parsers/dex/DexMapping';

export abstract class Artifact {
  content: Uint8Array;

  protected constructor(content: Uint8Array) {
    this.content = content;
  }
}

export interface AndroidArtifact {
  getDexMapping(): Promise<DexMapping | undefined>;
  getClassDefinitions(): Promise<ClassDefinition[]>;
  getManifest(): Promise<AndroidManifest>;
  getResourceTables(): Promise<ResourceTable[]>;
  getSignatureIdentifier(): Promise<string | undefined>;
}

export interface IOSArtifact {
  plist(): Promise<any | undefined>;

  getAppPlist(): Promise<any | undefined>;
  getMacosAppPlist(): Promise<any | undefined>;
  getWatchAppPlist(): Promise<any | undefined>;
  getAppClipPlist(): Promise<any | undefined>;
  getBinaryUUID(): Promise<string | undefined>;
}
