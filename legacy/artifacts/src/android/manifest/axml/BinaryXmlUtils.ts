import { compact } from 'lodash';
import { AndroidBinaryParser } from '../../../parsers/androidBinary/AndroidBinaryParser';
import { XmlAttribute } from '../../../parsers/androidBinary/AndroidBinaryParserTypes';
import { BinaryResourceTable } from '../../resources/binary/BinaryResourceTable';
import { AndroidManifest } from '../AndroidManifest';

export module BinaryXmlUtils {
  export async function binaryXmlToAndroidManifest(
    buffer: Buffer,
    binaryResourceTables: BinaryResourceTable[],
  ): Promise<AndroidManifest> {
    const xmlNode = new AndroidBinaryParser(buffer).parseXml();
    if (!xmlNode) {
      throw Error('Could not load binary manifest for APK.');
    }

    const manifestAttributes = xmlNode.attributes;
    const packageName = BinaryXmlUtils.getRequiredAttrValue(manifestAttributes, 'package', binaryResourceTables);
    const versionName = BinaryXmlUtils.getOptionalAttrValue(manifestAttributes, 'versionName', binaryResourceTables);
    const versionCode = BinaryXmlUtils.getOptionalAttrValue(manifestAttributes, 'versionCode', binaryResourceTables);

    const usesSdkElement = xmlNode.childNodes.find((node) => node.nodeName === 'uses-sdk');

    // We default to 1, since Android assumes 1 if not specified.
    const minSdkStr =
      BinaryXmlUtils.getOptionalAttrValue(usesSdkElement!.attributes, 'minSdkVersion', binaryResourceTables) ?? '1';
    const minSdkVersion = parseInt(minSdkStr, 10);

    // Get the list of permissions in the manifest.
    const permissions = compact(
      xmlNode.childNodes
        .filter((node) => node.nodeName === 'uses-permission')
        .map((node) => {
          if (node.attributes.length === 0) {
            return null;
          }
          return node.attributes.find((attr) => attr.name === 'name')?.value;
        }),
    );
    const applicationElement = xmlNode.childNodes.find((node) => node.nodeName === 'application');
    console.log(`Found application element: ${applicationElement}`);
    if (!applicationElement) {
      throw Error('Could not find application element in binary manifest.');
    }

    const iconPath = BinaryXmlUtils.getOptionalAttrValue(applicationElement.attributes, 'icon', binaryResourceTables);
    const label = BinaryXmlUtils.getOptionalAttrValue(applicationElement.attributes, 'label', binaryResourceTables);
    const usesCleartextTraffic =
      BinaryXmlUtils.getOptionalAttrValue(
        applicationElement.attributes,
        'usesCleartextTraffic',
        binaryResourceTables,
      ) === 'true';

    // Find the meta-data node with the Reaper instrumented name
    const metadataNodes = applicationElement.childNodes.filter((node) => node.nodeName === 'meta-data');
    const reaperMetadata = metadataNodes.find(
      (node) =>
        BinaryXmlUtils.getOptionalAttrValue(node.attributes, 'name', binaryResourceTables) ===
        'com.emergetools.reaper.REAPER_INSTRUMENTED',
    );
    const emergeReaperInstrumented = reaperMetadata?.attributes.find((attr) => attr.name === 'value')?.value === 'true';

    return {
      packageName,
      versionName,
      versionCode,
      minSdkVersion,
      permissions,
      application: {
        iconPath,
        label,
        usesCleartextTraffic,
        reaperInstrumented: emergeReaperInstrumented,
      },
      // split, isFeatureSplit, module is not relevant for binary XML parsing (i.e. from APKs).
      isFeatureSplit: false,
    };
  }

  export function getOptionalAttrValue(
    attributes: XmlAttribute[],
    name: string,
    binaryResTables: BinaryResourceTable[],
  ): string | undefined {
    const attribute = attributes.find((attr) => attr.name === name);

    if (!attribute) {
      console.log(`could not find attribute with name: ${name}`);
      return;
    }

    const value = attribute.value;
    if (!value || value === '') {
      console.log(`could not find string value for attribute with name: ${name}, trying to parse typedValue`);

      if (!attribute.typedValue) {
        console.log(`could not find typedValue for attribute with name: ${name}`);
        return;
      }

      switch (attribute.typedValue.type) {
        case 'string':
          return attribute.typedValue.value as string;
        case 'reference':
          return getResourceFromBinaryResourceFiles(attribute.typedValue.value, binaryResTables);
        case 'int_dec':
          return attribute.typedValue.value.toString();
        case 'dimension':
          return attribute.typedValue.value.value + attribute.typedValue.value.unit;
        case 'rgb8':
          return `#${attribute.typedValue.value.toString(16)}`;
        case 'argb8':
          return `#${attribute.typedValue.value.toString(16)}`;
        case 'boolean':
          return attribute.typedValue.value.toString();
        case 'unknown': {
          // Convert IEEE 754 integer representation to float
          const floatView = new Float32Array(1);
          const intView = new Int32Array(floatView.buffer);
          intView[0] = Number(attribute.typedValue.value);
          return floatView[0].toString();
        }
        default:
          console.log(`unsupported typedValue type: ${attribute.typedValue.type}`);
          return;
      }
    }

    // Special extra handling for string references
    if (value.startsWith('resourceId')) {
      return getResourceFromBinaryResourceFiles(value, binaryResTables);
    }

    return value;
  }

  export function getRequiredAttrValue(
    attributes: XmlAttribute[],
    name: string,
    binaryResTables: BinaryResourceTable[],
  ): string {
    const attr = getOptionalAttrValue(attributes, name, binaryResTables);
    if (!attr) {
      throw new Error(`Missing required attribute: ${name}`);
    }
    return attr;
  }

  export function getResourceFromBinaryResourceFiles(
    value: string,
    binaryResTables: BinaryResourceTable[],
  ): string | undefined {
    const values = binaryResTables.map((binaryResTable, i) => {
      try {
        return binaryResTable.getValueByStringId(value);
      } catch (e) {
        console.log(`Failed to get value from table ${i}:`, e);
        return undefined;
      }
    });

    return compact(values).pop();
  }
}
