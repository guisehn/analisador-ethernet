//
//  AppDelegate.m
//  AnalisadorEthernet
//
//  Trabalho 2 - Comunicação de Dados - UNISC
//  Desenvolvido por Guilherme Henrique Sehn (matr. 70326)
//

#import "AppDelegate.h"
#import <pcap.h>
#import <netinet/if_ether.h>

@implementation AppDelegate
@synthesize myArrayController;
@synthesize myTableView;
@synthesize tiposDados;

/**
 * Transforma bytes do endereço MAC em formato legível hexadecimal
 * Formato AA:BB:CC:DD:EE:FF
 */
- (NSString *) formatarMAC:(const u_char *)endereco
{
	return [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X", endereco[0], endereco[1], endereco[2], endereco[3], endereco[4], endereco[5]];
}

/**
 * Le pacote ethernet e retorna dictionary com dados formatados
 */
- (NSDictionary *) lerPacote:(const u_char *)packet header:(struct pcap_pkthdr)header
{
	const struct ether_header *ethernetHeader = (struct ether_header *)packet;
    
	// Calcula tamanho dos dados em bytes: caplen (? bytes) - destino (6 bytes) - fonte (6 bytes) - tipo (2 bytes)
	int tamanhoDados = header.caplen - 14;
	NSNumber *nsTamanhoDados = [NSNumber numberWithInt:tamanhoDados];
	
	// Calcula padding
	int padding = (tamanhoDados < 46) ? 46 - tamanhoDados : 0;
	NSNumber *nsPadding = [NSNumber numberWithInt:padding];
	
	// Soma padding ao tamanho do pacote
	int tamanhoPacote = header.caplen + padding;
	
	// Calcula tamanho do quadro: preâmbulo (7) + sd (1) + pacote (?) + crc (4 bytes)
	int tamanhoQuadro = 7 + 1 + tamanhoPacote + 4;
	NSNumber *nsTamanhoQuadro = [NSNumber numberWithInt:tamanhoQuadro];
	
	// Formata o tipo
	u_short tipoOuLength = ntohs(ethernetHeader->ether_type);
	NSString *strTipoOuLength = nil;
	NSString *tipoQuadro = nil;
	NSString *tipoDado = nil;
	
	if (tipoOuLength <= 0x05DC)
	{
		strTipoOuLength = [NSString stringWithFormat:@"%d bytes", tipoOuLength];
		tipoQuadro = @"IEEE 802.3";
	}
	else
	{
		tipoDado = [[self tiposDados] objectForKey:[NSString stringWithFormat:@"%04X", tipoOuLength]];
		tipoDado = (tipoDado != nil) ? tipoDado : @"?";
		
		strTipoOuLength = [NSString stringWithFormat:@"0x%04X (%@)", tipoOuLength, tipoDado];
		tipoQuadro = @"Ethernet DIX";
	}
	
	// Formata endereços de fonte e destino
	NSString *fonte = [self formatarMAC:ethernetHeader->ether_shost];
	NSString *destino = [self formatarMAC:ethernetHeader->ether_dhost];
	
	// Monta string dos dados em formato hexadecimal e texto
	NSMutableArray *bytesDadosHex = [[NSMutableArray alloc] init];
	NSMutableString *dadosTexto = [[NSMutableString alloc] init];
    
	for (int i = 6 + 6 + 2; i < header.caplen; i++)
	{
		[bytesDadosHex addObject:[NSString stringWithFormat:@"%02X", packet[i]]];
		
		// Só mostra bytes representando caracteres visiveis, caso contrário
		// usa o caractere . no lugar
		if (packet[i] >= 0x20 || packet[i] == 0x0A)
			[dadosTexto appendFormat:@"%c", packet[i]];
		else
			[dadosTexto appendString:@"."];
	}
    
	NSString *dadosHex = [bytesDadosHex componentsJoinedByString:@" "];
	
	// Retorna dictionary com os dados
	return [NSDictionary dictionaryWithObjectsAndKeys:
            tipoQuadro , @"TipoQuadro",
            fonte , @"Fonte",
            destino , @"Destino",
			strTipoOuLength , @"TipoOuLength",
			nsTamanhoQuadro , @"TamanhoQuadro",
            nsTamanhoDados , @"TamanhoDados",
            nsPadding , @"Padding",
            dadosHex , @"DadosHex",
            dadosTexto , @"DadosTexto", nil];
}

/**
 * Le e retorna conjunto de pacotes ethernet formatado
 */
- (NSArray *) lerPacotes:(pcap_t *) handle
{
	NSMutableArray *pacotes = [[NSMutableArray alloc] init];
    
	struct pcap_pkthdr header;
	const u_char *packet;
    
	while ((packet = pcap_next(handle, &header)))
	{
		[pacotes addObject:[self lerPacote:packet header:header]];
	}
	
	return [pacotes copy];
}

/**
 * Carrega arquivo pcap e popula tableview com os dados
 */
- (void) carregarArquivo:(NSString *)nomeArquivo
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline([nomeArquivo UTF8String], errbuf);
	
	// Cancela a leitura e avisa ao usuário caso a biblioteca não consiga abrir o arquivo
	if (handle == NULL)
	{
		NSAlert *alert = [[NSAlert alloc] init];
		[alert setMessageText:@"Erro ao abrir arquivo. Verifique se está em formato correto."];
		[alert beginSheetModalForWindow:[[NSApplication sharedApplication] mainWindow] completionHandler:nil];
		return;
	}
	
	// Popula controller do tableview com dados dos pacotes
	[myArrayController setContent:[self lerPacotes:handle]];
    
	pcap_close(handle);
}

/**
 * Método chamado ao clicar no botão "Carregar arquivo"
 * Abre diálogo para selecionar arquivo no computador do usuário.
 */
- (IBAction) clickCarregarArquivo:(id)sender {
	NSOpenPanel *dialog = [NSOpenPanel openPanel];
	
	[dialog setCanChooseFiles:YES];
	[dialog setCanChooseDirectories:NO];
	[dialog setAllowsMultipleSelection:NO];
	[dialog setAllowedFileTypes:[NSArray arrayWithObject:@"pcap"]];
	
	[dialog beginSheetModalForWindow:[[NSApplication sharedApplication] mainWindow] completionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 [self carregarArquivo:[[dialog URL] path]];
		 }
	 }];
}

/**
 * Método chamado ao clicar duas vezes em uma linha do tableview
 * Abre sheet com dados do quadro
 */
- (void) duploCliqueLinha:(id)object
{
	NSArray *selectedObjects = [myArrayController selectedObjects];
    
	if ([selectedObjects count] > 0)
	{
		NSDictionary *info = [selectedObjects objectAtIndex:0];
		
		NSTextField *textFieldHex = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 250, 200)];
		[textFieldHex setStringValue:[info objectForKey:@"DadosHex"]];
		[textFieldHex setFont:[NSFont fontWithName:@"Monaco" size:12.0]];
        
		NSTextField *textFieldTexto = [[NSTextField alloc] initWithFrame:NSMakeRect(260, 0, 250, 200)];
		[textFieldTexto setStringValue:[info objectForKey:@"DadosTexto"]];
		[textFieldTexto setFont:[NSFont fontWithName:@"Monaco" size:12.0]];
		
		NSView *accessoryView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 510, 200)];
		[accessoryView addSubview:textFieldHex];
		[accessoryView addSubview:textFieldTexto];
        
		NSMutableString *dadosQuadro = [[NSMutableString alloc] init];
		[dadosQuadro appendFormat:@"Tipo do quadro: %@\n", [info objectForKey:@"TipoQuadro"]];
		[dadosQuadro appendFormat:@"Fonte: %@", [info objectForKey:@"Fonte"]];
		[dadosQuadro appendFormat:@" | Destino: %@", [info objectForKey:@"Destino"]];
        
		if ([(NSString *)[info objectForKey:@"TipoQuadro"] isEqualToString:@"Ethernet DIX"])
		{
			[dadosQuadro appendFormat:@" | Tipo de dado: %@", [info objectForKey:@"TipoOuLength"]];
		}
		
		[dadosQuadro appendFormat:@"\nTamanho dos dados: %@ bytes", [info objectForKey:@"TamanhoDados"]];
		[dadosQuadro appendFormat:@" | Tamanho do padding: %@ bytes\n", [info objectForKey:@"Padding"]];
		[dadosQuadro appendFormat:@"Tamanho do quadro: %@ bytes\n", [info objectForKey:@"TamanhoQuadro"]];
		
		NSAlert *alert = [[NSAlert alloc] init];
		[alert setMessageText:@"Analisar quadro"];
		[alert setInformativeText:[dadosQuadro copy]];
		[alert setAccessoryView:accessoryView];
		[alert beginSheetModalForWindow:[[NSApplication sharedApplication] mainWindow] completionHandler:nil];
	}
}

- (void) applicationDidFinishLaunching:(NSNotification *)aNotification
{
	// Carrega arquivo plist com tipos de dados em um dictionary
	NSString *path = [[NSBundle mainBundle] pathForResource:@"TiposDados" ofType:@"plist"];
	self.tiposDados = [NSDictionary dictionaryWithContentsOfFile:path];
	
	// Seta evento de duplo clique em uma linha
	[myTableView setDoubleAction:@selector(duploCliqueLinha:)];
}

- (BOOL) applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application
{
	return YES;
}

@end
