/* Adapted From https://github.com/oblador/react-native-keychain */

#import <Security/Security.h>
#import "RNSensitiveInfo.h"
#import "React/RCTConvert.h"
#import "React/RCTBridge.h"
#import "React/RCTUtils.h"
#import <PadletSensitiveInfo/PadletSensitiveInfo.h>
#import "PLSensitiveInfoOptions+RNSensitiveInfo.h"

#if !TARGET_OS_TV
#import <LocalAuthentication/LocalAuthentication.h>
#endif

@interface RNSensitiveInfo ()

@property (nonatomic, strong, readonly) PLSensitiveInfoManager *sensitiveInfoManager;

@end

@implementation RNSensitiveInfo

@synthesize bridge = _bridge;
@synthesize sensitiveInfoManager = _sensitiveInfoManager;

RCT_EXPORT_MODULE();

- (PLSensitiveInfoManager *)sensitiveInfoManager {
    if (!_sensitiveInfoManager) { _sensitiveInfoManager = [[PLSensitiveInfoManager alloc] init]; }
    return _sensitiveInfoManager;
}

- (void)rejectError:(NSError *_Nonnull)error usingRejecter:(RCTPromiseRejectBlock)rejecter {
    if ([error.domain isEqualToString:PLSensitiveInfoErrorDomain]) {
        NSString *code = error.userInfo[PLSensitiveInfoErrorUserInfoKeyCode];
        NSString *message = error.userInfo[PLSensitiveInfoErrorUserInfoKeyMessage];
        rejecter(code, message, error);
    } else if ([error.domain isEqualToString:NSOSStatusErrorDomain]) {
        NSString *code = [NSString stringWithFormat:@"%ld", error.code];
        NSString *message = error.localizedDescription;
        rejecter(code, message, error);
    } else {
        rejecter(nil, error.localizedDescription, error);
    }
}

RCT_EXPORT_METHOD(setItem:(NSString*)key value:(NSString*)value options:(NSDictionary *)dictionary resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    PLSensitiveInfoOptions *options = [[PLSensitiveInfoOptions alloc] initWithDictionary:dictionary];
    NSError *error = nil;
    [self.sensitiveInfoManager setValue:value forItemWithKey:key options:options error:&error];
    if (error) {
        [self rejectError:error usingRejecter:reject];
    } else {
        resolve(value);
    }
}

RCT_EXPORT_METHOD(getItem:(NSString *)key options:(NSDictionary *)dictionary resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    PLSensitiveInfoOptions *options = [[PLSensitiveInfoOptions alloc] initWithDictionary:dictionary];
    [self.sensitiveInfoManager getValueForItemWithKey:key options:options dataProtectionStatusProvider:[UIApplication sharedApplication] completion:^(NSError * _Nullable error, NSString * _Nullable value) {
        if (error) {
            return [self rejectError:error usingRejecter:reject];
        } else {
            resolve(value);
        }
    }];
}

RCT_EXPORT_METHOD(getAllItems:(NSDictionary *)dictionary resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    PLSensitiveInfoOptions *options = [[PLSensitiveInfoOptions alloc] initWithDictionary:dictionary];
    NSArray<PLSensitiveInfoEntry *> *entries = [self.sensitiveInfoManager getAllItemsWithOptions:options];
    if (!entries.count) { return resolve(@[]); }
    NSMutableArray<NSDictionary<NSString *, id> *> *results = [NSMutableArray arrayWithCapacity:entries.count];
    for (PLSensitiveInfoEntry *entry in entries) {
        [results addObject:@{@"key": entry.key, @"value": entry.value, @"service": entry.service}];
    }
    resolve(results);
}


RCT_EXPORT_METHOD(deleteItem:(NSString *)key options:(NSDictionary *)dictionary resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    PLSensitiveInfoOptions *options = [[PLSensitiveInfoOptions alloc] initWithDictionary:dictionary];
    NSError *error = nil;
    [self.sensitiveInfoManager deleteItemWithKey:key options:options error:&error];
    if (error) {
        [self rejectError:error usingRejecter:reject];
    } else {
        resolve(nil);
    }
}

RCT_EXPORT_METHOD(isSensorAvailable:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
#if !TARGET_OS_TV
    if (@available(iOS 11.0, *)) {
        LAContext *context = [[LAContext alloc] init];
    
        NSError *evaluationError = nil;
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&evaluationError]) {
            if (@available(iOS 11, macOS 10.13.2, *)) {
                if (context.biometryType == LABiometryTypeFaceID) {
                    return resolve(@"Face ID");
                }
            }
            resolve(@"Touch ID");
        } else {
            if (evaluationError && evaluationError.code == LAErrorBiometryLockout) {
                return reject(nil, @"Biometry is locked", nil);
            }
            resolve(@(NO));
        }
    } else {
        resolve(@(NO));
    }
#else
  resolve(@(NO));
#endif
}
@end
