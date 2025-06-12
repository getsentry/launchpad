import { AndroidCodeUtils } from '../../android/utils/AndroidCodeUtils';

const NEWLINE = '\n'.charCodeAt(0);

export interface DexMappingClass {
  // The deobfuscated FQN of the class:
  name: string;

  // The deobfuscated signature of the class:
  signature: string;

  // The obfuscated FQN of the class:
  obfuscatedName: string;

  // The fileName if present:
  fileName?: string;

  // Start line within file. This may not be present even if fileName
  // is present.
  startLine?: number;
}

/**
 * Handles R8/Proguard mappings
 */
export class DexMapping {
  private classes: Map<string, DexMappingClass>;

  static parse(mappingBuffer: Buffer): DexMapping {
    const classes: DexMappingClass[] = [];
    let currentClass: DexMappingClass | undefined;
    const lines: string[] = [];

    let start = 0;
    for (let i = 0; i < mappingBuffer.length; ++i) {
      if (mappingBuffer[i] === NEWLINE) {
        const sub = mappingBuffer.subarray(start, i);
        const line = sub.toString('utf-8');
        lines.push(line);
        start = i + 1;
      }
    }

    // Parse the 'sourceFile' lines. The format of these lines is:
    // # {"id":"sourceFile","fileName":"CoroutineDebugging.kt"}
    const fileNameRe = /"fileName":"([^"]*)/;
    const parseComment = (line: string) => {
      // Ignore comments at the start of the file:
      if (!currentClass) {
        return;
      }
      const m = fileNameRe.exec(line);
      if (m) {
        const fileName = m[1];
        currentClass.fileName = fileName;
      }
    };

    const parseMethodOrMember = (line: string) => {
      // Format is one of:
      // originalfieldtype originalfieldname -> obfuscatedfieldname
      // [startline:endline:]originalreturntype [originalclassname.]originalmethodname(originalargumenttype,...)[:originalstartline[:originalendline]] -> obfuscatedmethodname
      // Square brackets are optional.

      // Currently we use the startLine of the first non-zero
      // method/member as the startLine of the class.
      // It's not clear if there is a more correct line number available.

      const trimmed = line.trim();
      const left = trimmed.split(' -> ')[0];
      const parts = left.split(':');
      const originalLineNumbers: number[] = [];
      for (let i = 0; i < Math.min(2, parts.length); ++i) {
        const part = parts[parts.length - i - 1];
        const n = Number(part);
        if (Number.isInteger(n)) {
          originalLineNumbers.unshift(n);
        }
      }
      const startLine = originalLineNumbers[0];
      if (currentClass) {
        if (currentClass.startLine === undefined) {
          currentClass.startLine = startLine;
        } else if (currentClass.startLine === 0) {
          currentClass.startLine = startLine;
        }
      }
    };

    const parseClass = (line: string) => {
      // Remove ':' suffix:
      line = line.slice(0, line.length - 1);

      // Split the line into obfuscated and original class names:
      const [name, obfuscatedName] = line.split(' -> ');
      if (name && obfuscatedName) {
        const signature = AndroidCodeUtils.fqnToClassSignature(name);
        const clazz = {
          name,
          signature,
          obfuscatedName,
        };

        classes.push(clazz);
        currentClass = clazz;
      }
    };

    for (const line of lines) {
      if (line.startsWith('#')) {
        parseComment(line);
      } else if (line.startsWith(' ')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#')) {
          parseComment(line);
        } else {
          parseMethodOrMember(line);
        }
      } else if (line.endsWith(':')) {
        parseClass(line);
      }
    }

    return new this(classes);
  }

  constructor(classes: DexMappingClass[]) {
    this.classes = new Map();
    for (const clazz of classes) {
      this.classes.set(clazz.obfuscatedName, clazz);
    }
  }

  size(): number {
    return this.classes.size;
  }

  deobfuscate(obfuscatedClassName: string): string | null | undefined {
    return this.classes.get(obfuscatedClassName)?.name ?? null;
  }

  deobfuscateSignature(obfuscatedSignature: string): string | null | undefined {
    return this.lookupObfuscatedSignature(obfuscatedSignature)?.signature ?? null;
  }

  lookupObfuscatedSignature(obfuscatedSignature: string): DexMappingClass | null | undefined {
    const obfuscatedFqn = AndroidCodeUtils.classSignatureToFqn(obfuscatedSignature);
    return this.lookupObfuscatedClass(obfuscatedFqn);
  }

  lookupObfuscatedClass(obfuscatedClassName: string): DexMappingClass | null | undefined {
    return this.classes.get(obfuscatedClassName);
  }

  lookupDeobfuscatedSignature(deobfuscatedClassSignature: string): DexMappingClass | null | undefined {
    const values = Array.from(this.classes.values());
    return values.find((clazz) => clazz.signature === deobfuscatedClassSignature);
  }
}
