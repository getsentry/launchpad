import { compact } from 'lodash';
import { ProtobufResourceTable } from '../../resources/proto/ProtobufResourceTable';
import { XmlAttribute, XmlNode } from '../../resources/proto/Resources';
import {
  AndroidManifest,
  AndroidManifestApplication,
  AndroidManifestModule,
  DeliveryType,
  ICON_RESOURCE_ID,
  LABEL_RESOURCE_ID,
  MIN_SDK_VERSION_RESOURCE_ID,
  VERSION_CODE_RESOURCE_ID,
  VERSION_NAME_RESOURCE_ID,
} from '../AndroidManifest';

export module ProtoXmlUtils {
  export function xmlProtoToAndroidManifest(
    name: string,
    manifestXmlContent: Uint8Array,
    protoResTables: ProtobufResourceTable[],
  ): AndroidManifest {
    const manifestNode = XmlNode.decode(manifestXmlContent);
    if (!manifestNode) {
      throw Error('Could not load JSON representation of base manifest for AAB.');
    }

    if (manifestNode.node?.$case !== 'element') {
      throw Error('Could not load JSON representation of base manifest element for AAB manifest.');
    }

    const manifestElement = manifestNode.node.element;
    const manifestAttributes = manifestElement.attribute;

    const packageName = ProtoXmlUtils.requiredAttrValueByName(manifestAttributes, 'package', protoResTables);
    const split = ProtoXmlUtils.optionalAttrValueByName(manifestAttributes, 'split', protoResTables);
    const isFeatureSplit =
      ProtoXmlUtils.optionalAttrValueByName(manifestAttributes, 'isFeatureSplit', protoResTables) === 'true';

    const versionName = ProtoXmlUtils.optionalAttrValueWithFallback(
      manifestAttributes,
      protoResTables,
      'versionName',
      VERSION_NAME_RESOURCE_ID,
    );
    const versionCode = ProtoXmlUtils.optionalAttrValueWithFallback(
      manifestAttributes,
      protoResTables,
      'versionCode',
      VERSION_CODE_RESOURCE_ID,
    );

    const usesSdkNode = ProtoXmlUtils.getOptionalElement(manifestNode, 'uses-sdk');
    let minSdkVersion: number;

    if (usesSdkNode!.node?.$case === 'element') {
      const usesSdkAttributes = usesSdkNode!.node.element.attribute;
      // We default to 1, since Android assumes 1 if not specified.
      const minSdkStr =
        ProtoXmlUtils.optionalAttrValueWithFallback(
          usesSdkAttributes,
          protoResTables,
          'minSdkVersion',
          MIN_SDK_VERSION_RESOURCE_ID,
        ) ?? '1';
      minSdkVersion = parseInt(minSdkStr, 10);
    } else {
      throw Error('Could not find uses-sdk element in manifest.');
    }

    // Get the list of permissions in the manifest.
    const permissions: string[] = compact(
      manifestNode.node?.element?.child
        ?.filter((child) => child.node?.$case === 'element' && child.node.element.name === 'uses-permission')
        .map((child) => {
          if (child.node?.$case !== 'element' || child.node.element.name !== 'uses-permission') {
            return null;
          }
          return child.node.element.attribute.find((attr) => attr.name === 'name')?.value;
        }),
    );

    const applicationElementNode = ProtoXmlUtils.getOptionalElement(manifestNode, 'application');

    let application: AndroidManifestApplication | undefined;
    if (applicationElementNode && applicationElementNode.node?.$case === 'element') {
      const applicationAttributes = applicationElementNode.node.element.attribute;
      if (applicationAttributes.length > 0) {
        application = {
          iconPath: ProtoXmlUtils.optionalAttrValueWithFallback(
            applicationAttributes,
            protoResTables,
            'icon',
            ICON_RESOURCE_ID,
          ),
          label: ProtoXmlUtils.optionalAttrValueWithFallback(
            applicationAttributes,
            protoResTables,
            'label',
            LABEL_RESOURCE_ID,
          ),
          usesCleartextTraffic:
            ProtoXmlUtils.optionalAttrValueByName(applicationAttributes, 'usesCleartextTraffic', protoResTables) ===
            'true',
          reaperInstrumented: (() => {
            const metaDataNodes = applicationElementNode.node.element.child.filter(
              (node) => node.node?.$case === 'element' && node.node.element.name === 'meta-data',
            );
            const reaperNode = metaDataNodes.find(
              (node) =>
                node.node?.$case === 'element' &&
                ProtoXmlUtils.optionalAttrValueByName(node.node.element.attribute, 'name', protoResTables) ===
                  'com.emergetools.reaper.REAPER_INSTRUMENTED',
            );
            if (!reaperNode) return false;

            return (
              reaperNode.node?.$case === 'element' &&
              ProtoXmlUtils.optionalAttrValueByName(reaperNode.node.element.attribute, 'value', protoResTables) ===
                'true'
            );
          })(),
        };
      }
    }

    const moduleElementNode: XmlNode | undefined = ProtoXmlUtils.getOptionalElement(manifestNode, 'module');

    console.log(`Processing manifest file: ${name}, moduleElementNode: ${JSON.stringify(moduleElementNode)}`);
    let module: AndroidManifestModule | undefined;
    if (moduleElementNode && moduleElementNode.node?.$case === 'element') {
      const moduleAttributes = moduleElementNode.node.element.attribute;

      const deliveryElementNode: XmlNode | null | undefined = ProtoXmlUtils.getOptionalElement(
        moduleElementNode,
        'delivery',
      );
      const isInstant = ProtoXmlUtils.optionalAttrValueByName(moduleAttributes, 'instant', protoResTables) === 'true';

      let deliveryType: DeliveryType | undefined;
      if (deliveryElementNode && deliveryElementNode.node?.$case === 'element') {
        const onDemandElementNode = ProtoXmlUtils.getOptionalElement(
          deliveryElementNode,
          DeliveryType.ON_DEMAND.toString(),
        );
        const installTimeElementNode = ProtoXmlUtils.getOptionalElement(
          deliveryElementNode,
          DeliveryType.INSTALL_TIME.toString(),
        );
        const fastFollowElementNode = ProtoXmlUtils.getOptionalElement(
          deliveryElementNode,
          DeliveryType.FAST_FOLLOW.toString(),
        );

        // Only one should be present, if two are present we'll loudly fail so we can support that case.
        if (onDemandElementNode) {
          deliveryType = DeliveryType.ON_DEMAND;
        } else if (installTimeElementNode) {
          deliveryType = DeliveryType.INSTALL_TIME;
        } else if (fastFollowElementNode) {
          deliveryType = DeliveryType.FAST_FOLLOW;
        } else {
          console.log(
            `Unknown delivery type for module ${deliveryElementNode.node.element.child}, defaulting to INSTALL_TIME`,
          );
          deliveryType = DeliveryType.INSTALL_TIME;
        }
      } else if (moduleAttributes.length > 0) {
        console.log(`No delivery element found for module ${name}, trying to find delivery type from attributes`);
        // Try to find the delivery type from the module attributes.
        // Some rare cases have shown no delivery element, but the delivery type is specified in the module attributes.
        const onDemandAttributeValue = ProtoXmlUtils.optionalAttrValueByName(
          moduleAttributes,
          'onDemand',
          protoResTables,
        );
        if (onDemandAttributeValue === 'true') {
          deliveryType = DeliveryType.ON_DEMAND;
        } else {
          console.log(`Unknown delivery type for module ${name}, defaulting to INSTALL_TIME`);
          deliveryType = DeliveryType.INSTALL_TIME;
        }
      }

      if (!deliveryType) {
        throw Error(
          `No delivery type found for module ${name} ${JSON.stringify(moduleElementNode.node.element.child)}, ${JSON.stringify(
            deliveryElementNode,
          )}`,
        );
      }

      if (moduleAttributes.length > 0) {
        let title;
        if (deliveryType === DeliveryType.INSTALL_TIME) {
          title = application?.label;
          if (!title) {
            if (split) {
              title = split;
            } else if (isInstant) {
              title = 'Instant App';
            } else {
              throw Error(`No title found for module ${name}`);
            }
          }
        } else {
          title = ProtoXmlUtils.requiredAttrValueByName(moduleAttributes, 'title', protoResTables);
        }

        module = {
          title,
          instant: isInstant,
          delivery: deliveryType,
        };
      }
    }

    return {
      packageName,
      split,
      versionName,
      versionCode,
      minSdkVersion,
      isFeatureSplit,
      permissions,
      application,
      module,
    };
  }

  /**
   * Dexguard and other obfuscation tools might remove the attribute name.
   * If name is not present, fallback to trying to find attribute based on resourceId.
   * For resourceId constants, see:
   * https://stuff.mit.edu/afs/sipb/project/android/docs/reference/android/R.attr.html
   */
  export function optionalAttrValueWithFallback(
    attributes: XmlAttribute[],
    protoResTables: ProtobufResourceTable[],
    name: string,
    resourceId: number,
  ): string | undefined {
    console.log(`optionalAttrValueWithFallback: ${name}, ${resourceId.toString(16)}`);
    let attrValue = optionalAttrValueByName(attributes, name, protoResTables);

    if (!attrValue) {
      console.log(`could not find attribute by name, trying to find by resourceId`);
      attrValue = optionalAttrValueByResourceId(attributes, resourceId, protoResTables);
    }

    return attrValue;
  }

  export function optionalAttrValueByName(
    attributes: XmlAttribute[],
    name: string,
    protoResTables: ProtobufResourceTable[],
  ): string | undefined {
    const attrFilter = (attr: XmlAttribute) => attr.name === name;
    return getOptionalAttrValue(attributes, protoResTables, attrFilter);
  }

  export function requiredAttrValueByName(
    attributes: XmlAttribute[],
    name: string,
    protoResTables: ProtobufResourceTable[],
  ): string {
    const attrFilter = (attr: XmlAttribute) => attr.name === name;
    const attr = getOptionalAttrValue(attributes, protoResTables, attrFilter);
    if (!attr) {
      throw new Error(`Missing required attribute: ${name}`);
    }
    return attr;
  }

  export function optionalAttrValueByResourceId(
    attributes: XmlAttribute[],
    resourceId: number,
    protoResTables: ProtobufResourceTable[],
  ): string | undefined {
    const attrFilter = (attr: XmlAttribute) => attr.resourceId === resourceId;
    return getOptionalAttrValue(attributes, protoResTables, attrFilter);
  }

  export function requiredAttrValueByResourceId(
    attributes: XmlAttribute[],
    resourceId: number,
    protoResTables: ProtobufResourceTable[],
  ): string {
    const attrFilter = (attr: XmlAttribute) => attr.resourceId === resourceId;
    const attr = getOptionalAttrValue(attributes, protoResTables, attrFilter);
    if (!attr) {
      throw new Error(`Missing required attribute: ${resourceId}`);
    }
    return attr;
  }

  // eslint-disable-next-line no-inner-declarations
  function getOptionalAttrValue(
    attributes: XmlAttribute[],
    protoResTables: ProtobufResourceTable[],
    attrFilter: (attr: XmlAttribute) => boolean,
  ): string | undefined {
    const attribute = attributes.filter(attrFilter)?.pop();

    if (!attribute) {
      console.log(`could not find attribute matching filter`);
      return;
    }

    const value = attribute.value;
    // Simple value not present, we'll want to check if a reference or primitive and see if we can pull
    if (!value || value === '') {
      console.log(`could not find string value for attribute matching filter, trying to parse compiled value`);

      if (!attribute.compiledItem) {
        console.log(`could not find compiledItem for attribute matching filter`);
        return;
      }

      const compiledItemValue = attribute.compiledItem.value;
      if (!compiledItemValue) {
        console.log(`could not find compiledItem.value for attribute matching filter`);
        return;
      }

      switch (compiledItemValue.$case) {
        case 'str':
          return compiledItemValue.str.value;
        case 'ref':
          // In cases of string references, we need to look up the actual string value
          if (compiledItemValue.ref.name) {
            return getResourceByKeyFromProtobufResourceFiles(compiledItemValue.ref.name, protoResTables);
          } else if (compiledItemValue.ref.id) {
            return getResourceByIdFromProtobufResourceFiles(compiledItemValue.ref.id, protoResTables);
          } else {
            console.error(`item.value.ref.id and item.value.ref.name are not defined.`);
            return;
          }
        case 'prim':
          switch (compiledItemValue.prim?.oneofValue?.$case) {
            case 'intDecimalValue':
              return compiledItemValue.prim.oneofValue.intDecimalValue.toString();
            case 'booleanValue':
              return compiledItemValue.prim.oneofValue.booleanValue.toString();
            default:
              console.log(
                `could not find primitive value for attribute matching filter, unknown type: ${compiledItemValue.prim?.oneofValue?.$case}`,
              );
              return;
          }
        default:
          console.log(
            `could not find string value for attribute matching filter, unknown type: ${compiledItemValue.$case}`,
          );
          return;
      }
    }

    // Special extra handling for string references
    if (value.startsWith('@')) {
      return getResourceByKeyFromProtobufResourceFiles(value, protoResTables);
    }

    return value;
  }

  export function getOptionalElement(element: XmlNode, name: string): XmlNode | undefined {
    if (element.node?.$case !== 'element') {
      console.log('element.node.$case is not element');
      return;
    }

    return element.node.element.child
      .filter((node, _, __) => {
        return node.node?.$case === 'element' && node.node?.element?.name === name;
      })
      ?.pop();
  }

  // eslint-disable-next-line no-inner-declarations
  function getResourceByKeyFromProtobufResourceFiles(
    key: string,
    resTables: ProtobufResourceTable[],
  ): string | undefined {
    const values = resTables.map((resTable, i) => {
      try {
        return resTable.getValueByKey(key);
      } catch (e) {
        console.log(`failed to get value by key: ${e}`);
        return undefined;
      }
    });
    return compact(values).pop();
  }

  // eslint-disable-next-line no-inner-declarations
  function getResourceByIdFromProtobufResourceFiles(
    id: number,
    resTables: ProtobufResourceTable[],
  ): string | undefined {
    const values = resTables.map((resTable, i) => {
      try {
        return resTable.getValueById(id);
      } catch (e) {
        console.log(`failed to get value by id: ${e}`);
        return undefined;
      }
    });
    return compact(values).pop();
  }
}
