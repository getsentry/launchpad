// Does normal json stringification except it handles bigints.
export function stringify(obj: any): string {
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'bigint') {
      return Number(value);
    }
    return value;
  });
}
