/* eslint-disable no-bitwise */

import { AndroidBinaryParser } from '../../../parsers/androidBinary/AndroidBinaryParser';
import { ResourceTablePackage, ResourceTableType } from '../../../parsers/androidBinary/AndroidBinaryParserTypes';
import { DEFAULT_PACKAGE_ID, ResourceTable } from '../ResourceTable';

export class BinaryResourceTable implements ResourceTable {
  binaryParser: AndroidBinaryParser;

  constructor(file: Buffer) {
    this.binaryParser = new AndroidBinaryParser(file);
    this.binaryParser.parseResourceTable();
  }

  static resourceIdFromString(value: string): number {
    return parseInt(value.replace('resourceId:', ''), 16);
  }

  getValueByKey(key: string): string | undefined {
    const appPackage = this.getApplicationPackage();
    if (!appPackage) {
      throw Error('No app package found in the resource table.');
    }

    const strings = appPackage.types.find(
      (type) => type.name === 'string' && type.config.language === '' && type.config.region === '',
    );
    if (!strings) {
      throw Error('No string type found in the app package.');
    }

    const entry = strings.entries.find((e) => e.key === key);
    if (!entry) {
      throw Error(`No string entry found with the name ${key}.`);
    }

    return entry.value?.value;
  }

  getValueByStringId(stringId: string): string | undefined {
    const intId = BinaryResourceTable.resourceIdFromString(stringId);
    return this.getValueById(intId);
  }

  getValueById(id: number): string | undefined {
    const typeId = (id >> 16) & 0xff;
    // TODO: Potentially support default configuration in the future
    const types = this.getTypesById(typeId);
    if (types.length === 0) {
      throw Error(`No type found in the resource table matching ${typeId}`);
    }

    const entryId = id & 0x0000ffff;
    // Types are based on configuration, but since ids appear to be unique across
    // different configs, we can just take the first match.
    const entry = types.flatMap((type) => type.entries).find((e) => e.id === entryId);

    if (!entry) {
      throw Error(`No entry found with the id ${entryId.toString(16)}.`);
    }

    const value = entry.value;
    if (!value) {
      throw Error(`No value found for entry with id ${entryId.toString(16)}.`);
    }

    switch (value.type) {
      case 'string':
        return value.value;
      case 'reference':
        return this.getValueByStringId(value.value);
      case 'rgb8':
        return `#${value.value.toString(16)}`;
      case 'argb8':
        return `#${value.value.toString(16)}`;
      default:
        throw Error(`Unsupported value type: ${value.type}`);
    }
  }

  private getApplicationPackage(): ResourceTablePackage | undefined {
    return this.binaryParser.packages.find((pkg) => pkg.id === DEFAULT_PACKAGE_ID);
  }

  private getTypesById(id: number): ResourceTableType[] {
    const resourcePackage = this.getApplicationPackage();
    if (!resourcePackage) {
      console.log('No resource package found in the resource table.');
      return [];
    }

    const types: ResourceTableType[] = resourcePackage.types.filter((type) => type.id === id);
    if (types.length === 0) {
      console.log(`No types found in the resource package matching id: ${id.toString(16)}`);
      return [];
    }
    return types;
  }
}
