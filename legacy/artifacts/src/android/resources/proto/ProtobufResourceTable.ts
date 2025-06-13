/* eslint-disable no-bitwise */
import { AndroidResourceUtils } from '../AndroidResourceUtils';
import { DEFAULT_PACKAGE_ID, ResourceTable } from '../ResourceTable';
import { Entry, Package, ResourceTable as PbResourceTable, Type, Value } from './Resources';

export class ProtobufResourceTable implements ResourceTable {
  readonly pbResourceTable: PbResourceTable;

  constructor(file: Buffer) {
    this.pbResourceTable = PbResourceTable.decode(file);
  }

  getValueByKey(key: string): string | undefined {
    let typeName = 'string';
    let trimmedKey = key;
    if (key.includes('/')) {
      const splits = key.split('/');
      typeName = splits[0].replace('@', '');
      trimmedKey = splits[1];
    }

    const stringType: Type | undefined = this.getTypesByName(typeName);
    if (!stringType) {
      if (typeName.startsWith('android:color')) {
        // Since we don't have android resources in the APK, we need to look up framework colors in AndroidResourceUtils.ANDROID_FRAMEWORK_COLORS
        // Note: this directly returns the color hex value
        const color = AndroidResourceUtils.ANDROID_FRAMEWORK_COLORS.get(key);
        if (color) {
          return color;
        }
      }
      console.log('No string type found in the resource package.');
      return;
    }

    const entry: Entry | undefined = stringType.entry.find((e) => e.name === trimmedKey);
    if (!entry) {
      console.log(`No string entry found with the name ${key}.`);
      return;
    }

    return this.getDefaultStringFromEntry(entry);
  }

  getValueById(id: number): string | undefined {
    // Type ID is the T elements of 0xPPTTEEEE
    const typeId = (id >> 16) & 0xff;
    const types = this.getTypesById(typeId);
    if (!types) {
      console.log(`No types found in the resource package matching ${typeId}`);
      return;
    }

    // Entry ID is the E elements of 0xPPTTEEEE
    const entryId = id & 0x0000ffff;
    const entry: Entry | undefined = types.entry.find((e) => e.entryId?.id === entryId);
    if (!entry) {
      console.log(`No string entry found with the id ${id}.`);
      return;
    }

    return this.getDefaultStringFromEntry(entry);
  }

  private getApplicationPackage(): Package | undefined {
    return this.pbResourceTable.package.find((pkg) => pkg.packageId?.id === DEFAULT_PACKAGE_ID);
  }

  // Default type is string
  private getTypesByName(typeName: string): Type | undefined {
    const resourcePackage = this.getApplicationPackage();
    if (!resourcePackage) {
      console.log('No resource package found in the resource table.');
      return;
    }

    const types: Type | undefined = resourcePackage.type.find((type) => type.name === typeName);
    if (!types) {
      console.log(`No types found in the resource package matching typeName: ${typeName}`);
      return;
    }
    return types;
  }

  private getTypesById(id: number): Type | undefined {
    const resourcePackage = this.getApplicationPackage();
    if (!resourcePackage) {
      console.log('No resource package found in the resource table.');
      return;
    }

    const types: Type | undefined = resourcePackage.type.find((type) => type.typeId?.id === id);
    if (!types) {
      console.log(`No types found in the resource package matching id: ${id.toString(16)}`);
      return;
    }
    return types;
  }

  private getDefaultStringFromEntry(entry: Entry): string | undefined {
    const entryValue: Value | undefined = entry.configValue?.find((config) => {
      // Default locale is empty string
      return config.config?.locale === '';
    })?.value;
    if (!entryValue) {
      console.log(`No default entry value found for entry ${entry.name}.`);
      return;
    }

    if (entryValue.value?.$case === 'item') {
      const item = entryValue.value.item;

      if (!item.value) {
        console.log(`No value found for entry ${entry.name}.`);
        return;
      }

      const itemCase = item.value.$case;
      switch (itemCase) {
        case 'str':
          return item.value.str.value;
        case 'ref':
          // One of id or name should be defined, so look up by whatever is present
          if (item.value.ref.name) {
            return this.getValueById(item.value.ref.id);
          } else if (item.value.ref.id) {
            // In cases of string references, we need to look up the actual string value
            return this.getValueByKey(item.value.ref.name);
          } else {
            console.error(`item.value.ref.id and item.value.ref.name are not defined.`);
            return;
          }
        case 'file':
          return item.value.file.path;
        case 'prim':
          switch (item.value.prim.oneofValue?.$case) {
            case 'intDecimalValue':
              return item.value.prim.oneofValue.intDecimalValue.toString();
            case 'booleanValue':
              return item.value.prim.oneofValue.booleanValue.toString();
            case 'colorRgb8Value':
              return item.value.prim.oneofValue.colorRgb8Value.toString();
            case 'colorArgb8Value':
              return item.value.prim.oneofValue.colorArgb8Value.toString();
            default:
              console.log(`Unsupported prim value: ${item.value.prim.oneofValue?.$case}`);
              return;
          }
        default:
          console.log(`Unsupported item case: ${itemCase}`);
      }
    } else {
      console.log(`No value found for entry ${entry.name}.`);
    }
  }
}
