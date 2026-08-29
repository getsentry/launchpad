class DexMapping:
  def deobfuscate_method(self, class_name, obfuscated_method_name):
    clazz = self.lookup_obfuscated_class(class_name)
    if clazz is None:
      clazz = self.lookup_deobfuscated_signature(class_name)

    if clazz is None or clazz.methods is None:
      return None

    return clazz.methods.get(obfuscated_method_name)

  def lookup_obfuscated_class(self, obfuscated_class_name):
    return self._classes.get(obfuscated_class_name)

  def lookup_deobfuscated_signature(self, deobfuscated_class_signature):
    for clazz in self._classes.values():
      if clazz.deobfuscated_signature == deobfuscated_class_signature:
        return clazz
    return None
