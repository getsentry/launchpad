export module AndroidCodeUtils {
  export function classSignatureToFqn(classSignature: string): string {
    // Remove leading 'L' and trailing ';' if they exist
    if (classSignature.startsWith('L')) {
      classSignature = classSignature.substring(1, classSignature.length);
    }
    if (classSignature.endsWith(';')) {
      classSignature = classSignature.substring(0, classSignature.length - 1);
    }

    return classSignature.replace(/\//g, '.');
  }

  export function fqnToClassSignature(fqn: string): string {
    fqn = fqn.replace(/\./g, '/');
    return `L${fqn};`;
  }

  export function removeKotlinSuffixFromSignature(classSignature: string): string {
    return classSignature.replace(/Kt(?=[$\/;])/, '');
  }

  export function removeKotlinSuffixFromFqn(fqn: string): string {
    return fqn.replace(/Kt(?=[$.]|\b)/, '');
  }
}
