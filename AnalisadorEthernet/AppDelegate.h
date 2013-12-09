//
//  AppDelegate.h
//  AnalisadorEthernet
//
//  Trabalho 2 - Comunicação de Dados - UNISC
//  Desenvolvido por Guilherme Henrique Sehn (matr. 70326)
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
{
    NSDictionary *tiposDados;
}

@property (nonatomic, retain) NSDictionary *tiposDados;

@property (assign) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSArrayController *myArrayController;
@property (weak) IBOutlet NSTableView *myTableView;
- (IBAction)clickCarregarArquivo:(id)sender;

@end
