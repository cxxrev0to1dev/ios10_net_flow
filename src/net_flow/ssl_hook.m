#import <dlfcn.h>
#import <stdio.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include "substrate.h"
#include <Foundation/NSString.h>
#include <Foundation/Foundation.h>
#include "logger.m"
#include "HookUtil.h"

//reference:
//https://github.com/zchee/libdispatch-sandbox/blob/master/dispatch_transform.c
static CFDataRef CFCreate(dispatch_data_t buf){
  const void* bytes;
  size_t size;
  dispatch_data_t m1 = dispatch_data_create_map(buf,&bytes,&size);
  assert(m1);
  CFDataRef d1 = CFDataCreate(kCFAllocatorDefault, bytes, size);
  assert(d1);
  dispatch_release(m1);
  return d1;
}
static void CFFree(CFDataRef data){
  if (data) {
    CFRelease(data);
  }
}
/////////////////////////////////////////////////////////
static id (*kSSLRawWrite)(void *self, dispatch_data_t,CFStreamError);
static id FnSSLRawWrite(void *self, dispatch_data_t buf,CFStreamError block_pointer){
  if (!buf) {
    return kSSLRawWrite(self,buf,block_pointer);
  }
  CFDataRef dataRef = CFCreate(buf);
  const char* byte = (const char*)CFDataGetBytePtr(dataRef);
  size_t size = CFDataGetLength(dataRef);
  if (!byte||!size) {
    CFFree(dataRef);
    return kSSLRawWrite(self,buf,block_pointer);
  }
  DEBUG_BYTE(byte,size);
  return kSSLRawWrite(self,buf,block_pointer);
  
  const char p[] = "POST /WebObjects/MZBuy.woa/wa/buyProduct";
  if (!memcmp(byte, p, sizeof(p) - sizeof(char))) {
    DEBUG_BYTE(byte,size);
    CFFree(dataRef);
    return kSSLRawWrite(self,buf,block_pointer);
  }
  if (!memcmp(byte, "GET ", 4)||!memcmp(byte, "POST ", 4)) {
    static NSString* t1 = @"Accept-Encoding";
    NSString *mod = @(byte);
    NSUInteger location = [mod rangeOfString:t1].location;
    if (location != NSNotFound) {
      NSRange range = NSMakeRange(location,1);
      NSString* s = [mod stringByReplacingCharactersInRange:
                     range withString:@"D"];
      mod = s;
      dispatch_data_t mod_data;
      dispatch_queue_t queue;
      long identifier;
      identifier = DISPATCH_QUEUE_PRIORITY_BACKGROUND;
      queue = dispatch_get_global_queue(identifier, 0);
      mod_data = dispatch_data_create([s UTF8String],
                                      [s length],
                                      queue, ^{});
      id result;
      DEBUG_BYTE(byte,size);
      result = kSSLRawWrite(self,mod_data,block_pointer);
      return result;
    }
  }
  DEBUG_BYTE(byte,size);
  return kSSLRawWrite(self,buf,block_pointer);
}
static OSStatus (*kSSLWrite) (SSLContextRef context,
                              const void *data,
                              size_t dataLength,
                              size_t *processed
                              );

static OSStatus FnSSLWrite (SSLContextRef context,
                            const void *data,
                            size_t dataLength,
                            size_t *processed
                            ){
  if (data&&dataLength) {
    DEBUG_BYTE(data,dataLength);
  }
  OSStatus ret = kSSLWrite(context,data,dataLength,processed);
  return ret;
}
static id (*kDeliverBodyBytes)(void *self,
                               dispatch_data_t,
                               CFStreamError,
                               bool);
static id FnDeliverBodyBytes(void *self,
                             dispatch_data_t buf,
                             CFStreamError block_pointer,
                             bool is){
  id result;
  if (!buf) {
    return kDeliverBodyBytes(self,buf,block_pointer,is);
  }
  CFDataRef dataRef = CFCreate(buf);
  const void* byte = CFDataGetBytePtr(dataRef);
  size_t size = CFDataGetLength(dataRef);
  if (size<1||!byte) {
    return kDeliverBodyBytes(self,buf,block_pointer,is);
  }
  DEBUG_BYTE(byte,size);
  result = kDeliverBodyBytes(self,buf,block_pointer,is);
  return result;
}
static void HookSSLRawRW(){
  const char* rs = "__ZN15TCPIOConnection4readEmmU13block_pointerFvP15dispatch_data_s13CFStreamErrorE";
  void* r = MSFindSymbol(NULL, rs);
  if(r){
    const char* ds = "__ZN10HTTPEngine17_deliverBodyBytesEP15dispatch_data_s13CFStreamErrorb";
    void* d = MSFindSymbol(NULL, ds);
    if(d){
      kDeliverBodyBytes = NULL;
      void* new_d = (void*)FnDeliverBodyBytes;
      MSHookFunction(d, new_d, (void **)&kDeliverBodyBytes);
      assert(kDeliverBodyBytes!=NULL);
    }
  }
  const char* ws = "__ZN15TCPIOConnection5writeEP15dispatch_data_sU13block_pointerFv13CFStreamErrorE";
  void* w = MSFindSymbol(NULL, ws);
  if(w){
    kSSLRawWrite = NULL;
    void* new_w = (void*)FnSSLRawWrite;
    MSHookFunction(w, new_w, (void **)&kSSLRawWrite);
    assert(kSSLRawWrite!=NULL);
  }
}
static void HookSystemRaw(){
  kSSLWrite = NULL;
  MSHookFunction((void*)SSLWrite,
                 (void *)FnSSLWrite, (void **)&kSSLWrite);
  assert(kSSLWrite!=NULL);
}
static CFTypeRef ForMGCopyAnswer(CFTypeRef prop){
  static CFTypeRef (*MGCopyAnswer)(CFTypeRef prop);
  if (!MGCopyAnswer) {
    const char* name = "MGCopyAnswer";
    MSImageRef image = MSGetImageByName("/usr/lib/libMobileGestalt.dylib");
    void* ptr = MSFindSymbol(image, name);
    if (!ptr) {
      ptr = MSFindSymbol(image, "_MGCopyAnswer");
      if (!ptr) {
        ptr = MSFindSymbol(NULL, "_MGCopyAnswer");
      }
    }
    MGCopyAnswer = (CFTypeRef(*)(CFTypeRef))ptr;
  }
  return MGCopyAnswer(prop);
}
static bool IsRequireUdidString(NSString* data){
  return (data&&[data isEqual:@"UniqueDeviceID"]);
}

static bool IsRequireUdidData(NSString* data){
  bool is_b = [data isEqual:@"UniqueDeviceIDData"];
  bool is_c = [data isEqual:@"nFRqKto/RuQAV1P+0/qkBA"];
  return (data&&(is_b||is_c));
}
HOOK_MESSAGE(id, SKUIClientContext,valueForConfigurationKey_,
             id arg1){
  if(arg1&&[arg1 isEqualToString:@"locale"]){
    return @"zh-CN";
  }
  return _SKUIClientContext_valueForConfigurationKey_(self,sel,arg1);
}
HOOK_MESSAGE(id, SKUIClientContext, storeFrontIdentifier){
  return @"143465-19,17";
}
__attribute__((constructor))
static void SSLReadWriteHooker(){
  NSLog(@"UniqueDeviceID:%@",ForMGCopyAnswer(@"UniqueDeviceID"));
  NSLog(@"UniqueDeviceIDData:%@",ForMGCopyAnswer(@"UniqueDeviceIDData"));
  NSLog(@"nFRqKto/RuQAV1P+0/qkBA:%@",ForMGCopyAnswer(@"nFRqKto/RuQAV1P+0/qkBA"));
  if (!SYSTEM_VERSION_LESS_THAN(@"10.0")) {
    HookSSLRawRW();
  }
  else{
    HookSystemRaw();
  }
}
