#ifndef FLUTTER_PLUGIN_SLIP39_DART_PLUGIN_H_
#define FLUTTER_PLUGIN_SLIP39_DART_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace slip39_dart {

class Slip39DartPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  Slip39DartPlugin();

  virtual ~Slip39DartPlugin();

  // Disallow copy and assign.
  Slip39DartPlugin(const Slip39DartPlugin&) = delete;
  Slip39DartPlugin& operator=(const Slip39DartPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace slip39_dart

#endif  // FLUTTER_PLUGIN_SLIP39_DART_PLUGIN_H_
