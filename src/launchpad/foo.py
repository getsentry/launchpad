class DexMapping:
  def __init__():
    self._classes_by_deobfuscated = [clazz.deobfuscated_signature for clazz in classes]

  def lookup_deobfuscated_signature(self, deobfuscated_class_signature):
    return self._classes_by_deobfuscated.get(deobfuscated_class_signature)
