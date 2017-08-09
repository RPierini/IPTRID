#!/bin/bash
#
#iptrid.sh - IPTRID (IPTables Rule IDentifier)
#
#------------------------------------------------------------------------------------
##Finalidade##
#Identifica matches em regras IPTables atraves de um pacote definido pelo usuario
#
##Fluxo Normal##
#-Solicita informacoes do pacote para o usuario
#-Toma a decisao de qual caminho de travessia sera realizado (INPUT, OUTPUT ou
#FORWARD) baseado no pacote definido pelo usuario
#-Percorre o RuleSet (todas as regras) verificando se ha match em alguma regra e
#adicionado em um Array com todos os matches
#-Demonstra atraves do caminho percorrido e das BuiltIn chains quais foram os matches
#alcancados e nao alcancados pelo pacote
#
##Requisitos##
#dialog - exibicao de interface grafica para o usuario
#grepcidr - testar se um endereco esta em uma subnet ou nao
#
##Autor##
#Rodrigo Pierini (RPIERINI) <rodrigo.alex@ifsp.edu.br>
#
##Historico##
#2017-08-03 v1: RPIERINI (primeira versao oficial)
#
##Limitacoes conhecidas##
#1) nao trabalha com matches em modulos (mac, mark, tos, etc),
#mas ao menos avisa o usuario que a regra nao foi processada
#2) nao trabalha com conexoes, pois nao utiliza o modulo conntrack
#3) nao trabalha com goto (parametro -g), mas trabalha com o parametro -j
#para chains do usuario
#4) nao trabalha com fragmentos de pacote (paramentro -f), pois nao trabalha com
#conexoes, portanto nao eh possivel simular uma conexao TCP para definir a
#fragmentacao do pacote
#
##Licenca##
#Prototipo desenvolvido como um projeto de TCC para o curso de Pos-graduacao Lato
#Sensu em Redes de Computadores da Escola Superior Aberta do Brasil (ESAB) em 2017
#Eh permitida a alteracao e reproducao do software desde que mantidos os creditos e
#a finalidade original de desenvolvimento do programa.
#
#------------------------------------------------------------------------------------
#

#Carregando variaveis que utilizaremos ao longo do programa
declare -A AEscopo #Array com o escopo da regra
declare -A APacote #Array com as infos do pacote
declare -A AMatch #Array com as regras que deram match

#temos que definir um stdout para o dialog funcionar
interface="dialog --stdout"

#Verifica as dependencias e informa ao usuario que devem ser instaladas para rodar.
function VerificarDependencias {
	for dependencia in "dialog" "grepcidr"; do
		if [ -z "$(which $dependencia 2> /dev/null)" ]; then
			echo "---Dependencia '$dependencia' nao instalada, necessaria para rodar!---"
			echo "Se voce esta utilizando Debian ou distribuicoes baseadas, utilize o comando 'sudo apt-get -y install $dependencia' para instalar"
			echo "Senao verifique a documentacao especifica da sua distribuicao linux para instalacao"
			exit 255
		fi
	done
}

#Funcao para verificar se o valor esta em um intervalo definido por "inicio:fim"
function VerificarIntervalo {
	if [ "$1" -ge "$(echo "$2" | cut -d":" -f1)" -a "$1" -le "$(echo "$2" | cut -d":" -f2)" ]; then echo "0"; else echo "1"; fi
}

#Funcao para sabermos a interface de saida de um pacote em FORWARD
function DefinirInterfaceSaida {
	#Percorremos a tabela de rotas do sistema
	for rota in $(netstat -nr | sed "s, * ,;,g" | sed "1,2d"); do
		ip="$(echo "$rota" | cut -d";" -f1)"

		#Se o IP de destino da rota for 0.0.0.0, entao sabemos o default gw do sistema
		if [ "$ip" = "0.0.0.0" ]; then defaultgw="$(echo "$rota" | cut -d";" -f8)"; continue 1; fi

		netmask="$(TraduzirNetmask "$(echo "$rota" | cut -d";" -f3)")"
		#Senao, verificamos se o IP de destino se encaixa no subnet da rota
		if [ "$(IPSubrede "${1}" "${ip}/${netmask}")" -eq 0 ]; then
			#Caso encaixe, guardamos a interface e paramos a busca
			onet="$(echo "$rota" | cut -d";" -f8)"
			break 1
		fi
	done

	#Se nao encontramos a interface de saida, definimos como o defaultgw, senao escrevemos em branco pois nao ha interface
	if [ -z "$onet" ]; then onet="$defaultgw"; fi
	echo "$onet"
}

#Escreve uma string com os valores das flags de acordo com o tipo de array do programa"
function EscreverStringArray {
	case $1 in
	escopo)
		for flag in "fSRCIP" "fDSTIP" "fPROT" "fINET" "fONET" "fMATCH" "fTARGET" "fSPORT" "fDPORT" "fSNAT" "fDNAT" "fREDIRECT" "fMODULE"; do
			echo -n "${flag};${AEscopo[$flag]},"
		done;;
	pacote)
		for flag in "fSRCIP" "fSRCNM" "fDSTIP" "fDSTNM" "fPROT" "fSPORT" "fDPORT" "fINET" "fONET"; do
			echo -n "${APacote[$flag]},"
		done;;
	esac
	echo ""
}

#Function para carregar a variavel AEscopo
function CarregarArrayEscopo {
	for indice in $(echo "$1" | sed "s/,/ /g"); do
		flag="$(echo "$indice" | cut -d";" -f1)"
		valor="$(echo "$indice" | cut -d";" -f2)"
		AEscopo[$flag]="$valor"
	done
}

#Funcao para identificar a interface que utiliza um certo endereco IP, ou em branco caso nao encontre
function GetInterfaceEndereco {
	echo "$(ip -o addr | grep "$1" | sed "s, * ,;,g" | cut -d";" -f2)"
}

#Funcao para identificar o endereco IP de uma interface
function GetEnderecoInterface {
	echo "$(ip -o addr | sed "s, * ,;,g" | grep "${1};inet;" | cut -d";" -f4 | cut -d"/" -f1)"
}

#Funcao para identificar os enderecos locais do computador, para sabermos a decisao de roteamento na travessia
function GetEnderecosLocais {
	echo "$(ip -o addr | grep "inet " | sed "s, * ,;,g" | cut -d";" -f4 | cut -d"/" -f1)"
}

#Funcao para exibir ao usuario os matches das BuiltIn Chains
function ExibirMatchesTableChain {
	IFSBKP=$IFS
	IFS="\
"
	msg=()
	for match in ${AMatch[@]}; do
		if [ -n "$(echo "$match" | grep ";${1};${2};")" ]; then
			definitivo="$(echo "$match" | cut -d";" -f1)"
			regra="$(echo "$match" | cut -d";" -f4)"
			tipo_match="$(case $definitivo in 0)echo "definitivo:";; 1)echo "nao atingido:";; 2)echo "entrar chain:";; 3)echo "nao processado:";; esac)"
			msg+=("Match $tipo_match $regra")
		fi
	done
	texto="Matches na Table '${1}' e Chain '${2}':\n"
	if [ ${#msg[@]} -eq 0 ]; then
		texto="${texto}Nao houve Matchs.\nPolitica padrao da chain: '$(iptables -t ${1} -S ${2} | grep '\-P' | cut -d" " -f3)'"
	else
		for linha in ${msg[@]}; do
			texto="$texto$linha\n"
		done
	fi
	IFS=$IFSBKP
	$interface --title "Matches em ${1}:${2}" --msgbox "$texto" 20 120
}

#Funcao para gerar a estrutura do escopo da regra
function GerarEscopo {
	#Declaramos um Array que fara o trabalho de uma estrutura para definir o escopo da regra
	regra="$@"
	declare -A escopo
	escopo=()
	flagnot=0

	#Percorremos a regra separando cada argumento
	for arg in ${regra}; do
		valor=""
		#Identificamos se e um identificador de parametro ou um valor e definimos a flag para o que estamos trabalhando
		case $arg in
			-s) flag="fSRCIP";;
			-d) flag="fDSTIP";;
			-p) flag="fPROT";;
			-i) flag="fINET";;
			-o) flag="fONET";;
			-m) flag="fMODULE";;
			-j) flag="fTARGET";;
			--sport) flag="fSPORT";;
			--dport) flag="fDPORT";;
			--to-destination) flag="fDNAT";;
			--to-source) flag="fSNAT";;
			--to-port) flag="fREDIRECT";;
			"!") flagnot="1";;
			*) valor="$arg"
		esac

		#Se tivermos um valor e uma flag definida, ja podemos atribuir o valor a ela
		if [ -n "$flag" ] && [ -n "$valor" ]; then
			#Verificamos se a flag do NOT esta ativa, se estiver, ja temos de colocar o not antes do valor
			if [ $flagnot -eq 0 ]; then
				#Se for um modulo, que podemos ter varios definidos, adicionamos ele na lista da flag
				if [ "$flag" = "fMODULE" ]; then
					escopo[$flag]="${escopo[$flag]}:$valor"
				else
					escopo[$flag]="$valor"
				fi
			else
				escopo[$flag]="!$valor"
				flagnot="0"
		fi
			flag=""
		fi
	done

	#Alguns ajustes para evitarmos campos em branco
	#se o SRCIP ou DSTIP estiver em branco, definimos como 0.0.0.0/0
	flags=("fSRCIP" "fDSTIP")
	for flag in ${flags[@]}; do
		if [ -z "${escopo[$flag]}" ]; then escopo[$flag]="0.0.0.0/0"; fi
	done
	#se o PROT,INET,ONET,MODULE,SPORT e DPORT estiverem em branco, definimos como ANY
	flags=("fPROT" "fINET" "fONET" "fMODULE" "fSPORT" "fDPORT")
	for flag in ${flags[@]}; do
		if [ -z "${escopo[$flag]}" ]; then escopo[$flag]="ANY"; fi
	done

	#escrevendo o array para a saida
	flags=("fSRCIP" "fDSTIP" "fPROT" "fINET" "fONET" "fMODULE" "fTARGET" "fSPORT" "fDPORT" "fSNAT" "fDNAT" "fREDIRECT")
	for flag in ${flags[@]}; do
		echo -n "${flag};${escopo[$flag]},"
		AEscopo[$flag]="${escopo[$flag]}"
	done
	echo ""
}

#Funcao para ver se o pacote se encaixa a regra, retorna 0 para match e 1 para nao match
function AvaliarMatch {
	#Para um pacote dar match, ele deve atender todo o escopo da regra, entao vamos percorrer a estrutura da regra para verificar
	#pacote="$1"
	#escopo="$2"

	#Vamos dividir o conteudo do pacote em variaveis
	pSRCIP="${APacote[fSRCIP]}/${APacote[fSRCNM]}"
	pDSTIP="${APacote[fDSTIP]}/${APacote[fDSTNM]}"
	pPROT="${APacote[fPROT]}"
	pSPORT="${APacote[fSPORT]}"
	pDPORT="${APacote[fDPORT]}"
	pINET="${APacote[fINET]}"
	pONET="${APacote[fONET]}"

	#pegamos o comprimento do escopo para percorrer
	for campo in $(echo "$escopo" | sed 's/,/ /g'); do
		flagnot=0
		flag="$(echo "$campo" | cut -d";" -f1)"
		valor="$(echo "$campo" | cut -d";" -f2)"

		#tratando os not
		if [ "${valor:0:1}" = "!" ]; then flagnot=1; fi

		#Tratamos o match para cada flag encontrada no escopo
		#Se for SRCIP ou DSTIPT e estiver como 0.0.0.0/0 (qualquer IP), entao eh match direto, senao avaliamos
		#Se for SPORT ou DPORT e estiver como ANY no escopo ou no pacote, entao eh match direto, senao avaliamos
		#Se for um intervalo de portas (possui um : no meio do valor), verificamos se a porta esta dentro
		#do intervalo para podermos conisderar o match, se nao tiver :, verificamos se eh exatamente igual
		#Para os demais, se o escopo esta ANY (nao especificado), entao eh match direto, senao avaliamos
		case $flag in
			"fSRCIP") if [ "$valor" = "0.0.0.0/0" ]; then
					mSRCIP=0
				elif [ $(IPSubrede "$pSRCIP" $valor) -eq 0 ]; then
					mSRCIP=0
				else
					mSRCIP=1
				fi; mSRCIP=$((${mSRCIP} ^ ${flagnot}));;
			"fDSTIP") if [ "$valor" = "0.0.0.0/0" ]; then
					mDSTIP=0
				elif [ $(IPSubrede "$pDSTIP" $valor) -eq 0 ]; then
					mDSTIP=0
				else
					mDSTIP=1
				fi; mDSTIP=$((${mDSTIP} ^ ${flagnot}));;
			"fPROT") if [ "$valor" = "ANY" ]; then mPROT=0; else mPROT="$(if [ "$pPROT" = "$valor" ]; then echo "0"; else echo "1"; fi)"; fi
				mPROT=$((${mPROT} ^ ${flagnot}));;
			"fSPORT") if [ "$valor" = "ANY" ] || [ "$pSPORT" = "ANY" ]; then
					mSPORT=0
				elif [ -z "${valor##*:*}" ]; then
					mSPORT=$(VerificarIntervalo $pSPORT "$valor")
				else
					mSPORT="$(if [ "$pSPORT" = "$valor" ]; then echo "0"; else echo "1"; fi)"
				fi; mSPORT=$((${mSPORT} ^ ${flagnot}));;
			"fDPORT") if [ "$valor" = "ANY" ] || [ "$pDPORT" = "ANY" ]; then
					mDPORT=0
				elif [ -z "${valor##*:*}" ]; then
					mDPORT=$(VerificarIntervalo $pDPORT "$valor")
				else
					mDPORT="$(if [ "$pDPORT" = "$valor" ]; then echo "0"; else echo "1"; fi)"
				fi; mDPORT=$((${mDPORT} ^ ${flagnot}));;
			"fINET") if [ "$valor" = "ANY" ]; then mINET=0; else mINET="$(if [ "$pINET" = "$valor" ]; then echo "0"; else echo "1"; fi)"; fi
				mINET=$((${mINET} ^ ${flagnot}));;
			"fONET") if [ "$valor" = "ANY" ]; then mONET=0; else mONET="$(if [ "$pONET" = "$valor" ]; then echo "0"; else echo "1"; fi)"; fi
				mONET=$((${mONET} ^ ${flagnot}));;
		esac
	done

	#Se tudo der MATCH, retornamos 0, senao retornamos 1
	if [ $mSRCIP -eq 0 ] && [ $mDSTIP -eq 0 ] && [ $mPROT -eq 0 ] && [ $mSPORT -eq 0 ] && [ $mDPORT -eq 0 ] && [ $mINET -eq 0 ] && [ $mONET -eq 0 ]; then
		echo 0
	else
		echo 1
	fi
}

#Funcao para percorrer o ruleset para procurar por matchs
function PercorrerRuleset {
	local Table="$1"
	local Chain="$2"
	local definitivo="$3"
	qtd_match="$4"

	#Pegamos todo o Ruleset da Chain na Table especificada
	local ruleset=$(iptables -t $Table -S $Chain)
	#Pegamos o numero de regras para percorrer
	local num_regras="$(echo "$ruleset" | wc -l)"

	caminhopercorrido="${caminhopercorrido}${Table}:${Chain} => "

	#Fazemos a iteracao por regra
	for i in $(seq 1 $num_regras); do
		#Avaliamos o primeiro parametro da regra, se for -P (politica padrao) ou -N (nova chain), pulamos
		local regratoda="$(echo "$ruleset" | head -n${i} | tail -n1)"
		if [ "$(echo "$regratoda" | cut -d" " -f1)" = "-P" ] || [ "$(echo "$regratoda" | cut -d" " -f1)" = "-N" ]; then continue 1; fi

		#Retiramos a primeira parte (-A Chain) da regra pois nao muda e nao nos interessa
		local regra="$(echo "$regratoda" | cut -d" " -f3-)"

		local escopo="$(GerarEscopo $regra)"

		AEscopo=()
		CarregarArrayEscopo "$escopo"

		#Parada significa que tivemos um DROP ou um REJECT, ou um ACCEPT na chain, portanto nada mais dara um match definitivo pois o pacote nao existira mais
		if [ $parada -eq 1 ] || [ $paradaChain -eq 1 ]; then
			local definitivo=1
		fi

		if [ $(AvaliarMatch "$pacote" "$escopo") -eq 0 ]; then

			#Aumentamos a quantidade de match e guardamos a informacao da regra para caso entremos em outra chain
			#Antes de escrever o resultado do match (final da funcao)
			let qtd_match++
			match=";$Table;$BuiltinChain;iptables -t $Table $regratoda"

			#Se tivermos um modulo e ele nao for nem tcp e nem udp (por causa do protocol) e nem ANY,
			#entao colocamos como nao processada para informar o usuario e pulamos para a proxima regra
			if [ -n "${AEscopo[fMODULE]}" ] && [ "${AEscopo[fMODULE]}" != ":tcp" ] && \
			[ "${AEscopo[fMODULE]}" != ":udp" ] && [ "${AEscopo[fMODULE]}" != "ANY" ]; then
				AMatch[$qtd_match]="3${match}"
				continue 1
			fi

			#Se o TARGET for ACCEPT, DROP ou REJECT, entao o iptables netfilter pararia nessa regra na builtin chain
			#Se o TARGET for um RETURN, nos paramos de processar a chain atual e voltamos para a chain acima, ou partimos para a proxima
			if [ $parada -eq 0 ] && [ $paradaChain -eq 0 ]; then
				case ${AEscopo[fTARGET]} in
					ACCEPT) definitivo=0; paradaChain=1;;
					DROP|REJECT) definitivo=0; parada=1;;
					RETURN) AMatch[$qtd_match]="0${match}"; break 1;;
				esac
			fi

			#Verificamos se a TARGET eh uma chain do usuario
			for chainusuario in ${chainsusuario[@]}; do
				#Pegamos a tabela das chains do usuario para saber se a chain pertence a tabela que estamos trabalhando
				#Se nao pertencer, pulamos para validar a proxima chain do usuario
				local Ltable="$(echo "$chainusuario" | cut -d";" -f1)"
				if [ "$Ltable" != "$Table" ]; then continue 1; fi

				#Se for da tabela, pegamos a chain e verificamos se o TARGET e daquela chain
				local Lchain="$(echo "$chainusuario" | cut -d";" -f2)"
				if [ ${AEscopo[fTARGET]} = "$Lchain" ]; then
					#Se esse seria o Match definitivo, nao deixamos ser por nao ser um fim da builtin chain
					#if [ $definitivo -eq 0 ]; then definitivo=1; fi
					AMatch[$qtd_match]="2${match}"

					#Se der TARGET na chain do usuario, percorremos ela
					let nivel++
					PercorrerRuleset $Table $Lchain $definitivo $qtd_match
					let nivel--
					break 1
				fi
			done

			#Agora veificamos se o pacote esta na tabela NAT e se a target eh DNAT, SNAT, MASQUERADE ou ACCEPT para
			#tratarmos o pacote ou pularmos a decisao de nat.

			#SNAT: Trocamos o IP de origem do pacote pelo definido na regra de SNAT e paramos de verificar regras de NAT na CHAIN
			#DNAT: Trocamos o IP de destino do pacote pelo definido na regra de DNAT e paramos de verificar regras de NAT na CHAIN
			#MASQUERADE: Trocamos o IP de origem do pacote pelo IP de origem da interface que ele ira sair e paramos de verificar regras de NAT na CHAIN
			#ACCEPT: paramos de verificar regras de NAT na CHAIN
			if [ $Table = "nat" ]; then
				definitivo=1
				case ${AEscopo[fTARGET]} in
					SNAT) APacote[fSRCIP]="${AEscopo[fSNAT]}"; pacote="$(EscreverStringArray "pacote")";;
					DNAT) APacote[fDSTIP]="${AEscopo[fDNAT]}"; pacote="$(EscreverStringArray "pacote")";;
					MASQUERADE) APacote[fSRCIP]="$(GetEnderecoInterface "${APacote[fONET]}")"; pacote="$(EscreverStringArray "pacote")";;
					REDIRECT) APacote[fDPORT]="${AEscopo[fREDIRECT]}"; pacote="$(EscreverStringArray "pacote")";;
				esac
			fi

			AMatch[$qtd_match]="${definitivo}${match}"
		fi
	done
}

#Funcao para definir o caminho que percorreremos as regras
function DefinirCaminho {
	#Agora, pelos IPs de origem e destino do pacote gerado, vamos descobrir se ele esta entrando, saindo ou encaminhado o pacote do kernel
	caminho=""
	if [ "${APacote[fSRCIP]}/${APacote[fSRCNM]}" = "$(GetEnderecoInterface "${APacote[fONET]}")/32" ]; then caminho="out"
	elif [ "${APacote[fDSTIP]}/${APacote[fDSTNM]}" = "$(GetEnderecoInterface "${APacote[fINET]}")/32" ]; then caminho="in"
	fi
	#Se nao eh nem entrada nem saida, entao esta encaminhando
	if [ -z "$caminho" ]; then caminho="forward"; fi

	#Agora vamos ter um array para definir quais tables e chains builtin devemos percorrer
	#Para cada caso de caminho, adicionamos as chains por onde vamos passar
	#Se houverem chains definidas pelo usuario, sera tratada pelos "Targets"
	case $caminho in
		"in")tablechains=("mangle:PREROUTING" "nat:PREROUTING" "mangle:INPUT" "filter:INPUT");;
		"out")tablechains=("mangle:OUTPUT" "nat:OUTPUT" "filter:OUTPUT" "mangle:POSTROUTING" "nat:POSTROUTING");;
		"forward")tablechains=("mangle:PREROUTING" "nat:PREROUTING" "mangle:FORWARD" "filter:FORWARD" "mangle:POSTROUTING" "nat:POSTROUTING");;
	esac

	echo "${tablechains[@]}"
}

#Funcao para traduzir netmask em bitwisse para cidr
function TraduzirNetmask {

	#Poderia reduzir isso tudo em uma linha usando "bc", mas quero evitar adicionar mais dependencias ao programa
	case $1 in
		255.255.255.255) echo "32";;
		255.255.255.254) echo "31";;
		255.255.255.252) echo "30";;
		255.255.255.248) echo "29";;
		255.255.255.240) echo "28";;
		255.255.255.224) echo "27";;
		255.255.255.192) echo "26";;
		255.255.255.128) echo "25";;
		255.255.255.0) echo "24";;
		255.255.254.0) echo "23";;
		255.255.252.0) echo "22";;
		255.255.248.0) echo "21";;
		255.255.240.0) echo "20";;
		255.255.224.0) echo "19";;
		255.255.192.0) echo "18";;
		255.255.128.0) echo "17";;
		255.255.0.0) echo "16";;
		255.254.0.0) echo "15";;
		255.252.0.0) echo "14";;
		255.248.0.0) echo "13";;
		255.240.0.0) echo "12";;
		255.224.0.0) echo "11";;
		255.192.0.0) echo "10";;
		255.128.0.0) echo "9";;
		255.0.0.0) echo "8";;
		254.0.0.0) echo "7";;
		252.0.0.0) echo "6";;
		248.0.0.0) echo "5";;
		240.0.0.0) echo "4";;
		224.0.0.0) echo "3";;
		192.0.0.0) echo "2";;
		128.0.0.0) echo "1";;
		0.0.0.0) echo "0";;
	esac
}

#Funcao para verificar se um IP esta na SubRede, precisa do grepcidr
function IPSubrede {
	grepcidr "$2" <(echo "$1") > /dev/null && echo "0" || echo "1"
}

#Funcao para consistir se um IP digitado eh valido
function ConsistirIP {
	#Primeiro verificamos se ele possui 3 pontos delimitando
	if [ $(echo -n "${1//[^.]}" | wc -c) -ne 3 ]; then return 1; fi

	#Verificamos agora se todos os octetos possuem um valor e se sao numeros
	#Verificamos cada octeto individualmente agora
	for i in $(seq 1 4); do
		octeto_atual="$(echo ${1} | cut -d"." -f${i})"

		#Se estiver vazio, retorna 1 (invalido)
		if [ -z "$octeto_atual" ]; then return 1; fi
		#Se nao for numero, retorna 1 (invalido)
		re='^[0-9]+$'
		if ! [[ $octeto_atual =~ $re ]]; then return 1; fi
		#Se for menor que 0 ou maior que 255, retorna 1 (invalido)
		if [ $octeto_atual -lt 0 ] || [ $octeto_atual -gt 255 ]; then return 1; fi
	done

	#Se for mascara de subrede, para cada octeto maior que 0, verificamos se os anteriores sao 255
	#Alem disso, cada octeto so pode fazer parte do grupo 0 128 192 224 240 248 252 254 e 255
	if [ -n "$2" ] && [ "$2" = "mascara" ]; then
		for i in $(seq 4 -1 1); do
			octeto_atual="$(echo ${1} | cut -d"." -f${i})"

			#Verificamos se o octeto esta no grupo aceitavel de valores
			vlr_aceitavel=("0" "128" "192" "224" "240" "248" "252" "254" "255")
			if ! [[ " ${vlr_aceitavel[@]} " =~ " $octeto_atual " ]]; then return 1; fi

			#Verificamos agora se o octeto for maior que 0, os anteriores devem ser 255
			if [ ${octeto_atual} -gt 0 ]; then
				for j in $(seq $((${i}-1)) -1 1); do
					octeto_anterior="$(echo ${1} | cut -d"." -f${j})"
					if [ $octeto_anterior -ne 255 ]; then return 1; fi
				done
			fi
		done
	fi

	return 0
}

#ListaTodas as Regras para o Usuario
function ListarRegras {
	$interface --title "Navegacao" --msgbox "Para navegar em listas grandes, utilize o Page Up e Page Down!" 0 0

	if [ $Table = "todas" ]; then
		for tabela in filter nat mangle; do
			$interface --title " Todas as Regras: ${tabela} " --msgbox "$(iptables -t $tabela -S)" 0 0
		done
	else
		for chain in ${Chain[@]}; do
			$interface --title " Tabela: ${Table} - ${chain} " --msgbox "$(iptables -t $Table -S $chain)" 0 0
		done
	fi
}

#Function para carregar as chains do usuario
function CarregarChainsUsuario {
	chainsusuario=()
	for tabela in "filter" "nat" "mangle"; do
		chainsusuariotabela=($(iptables -t "$tabela" -S | grep "\-N" | cut -d" " -f2))
		for chain in ${chainsusuariotabela[@]}; do
			chainsusuario=(${chainsusuario[@]} "$tabela;$chain");
		done
	done
	echo "${chainsusuario[@]}"
}

#Function para gerar uma lista de opcoes para o Dialog a partir de um Array
function GerarListaArray {
	array=($@)
	lista=""
	for i in $(seq 1 1 ${#array[@]}); do
		lista="$lista $i ${array[$i-1]} off"
	done
	echo $lista
}

#Function para selecionar a chain que ira trabalhar
function MenuSelecionarChain {
	#De acordo com a tabela ja carregamos um array com as chains predefinidas
	case $Table in
		filter) chains=("INPUT" "OUTPUT" "FORWARD");;
		nat) chains=("PREROUTING" "FORWARD" "POSTROUTING");;
		mangle) chains=("PREROUTING" "INPUT" "OUTPUT" "FORWARD" "POSTROUTING");;
	esac

	#Agora adicionamos as chains definidas pelo usuario
	chains=(${chains[@]} $(iptables -t $Table -S | grep '\-N' | cut -d" " -f2 | tr '\n' ' '))

	#E pedimos para escolher com qual chain deseja trabalhar
	opcoes=($($interface --title "Selecionar Chain" --checklist "Qual chain voce deseja trabalhar?" 0 0 0 \
		$(GerarListaArray ${chains[@]})))

	unset Chain
	for opcao in ${opcoes[@]}; do
		Chain=(${Chain[@]} "${chains[$opcao-1]}")
	done
}

#Function da funcao de listar regras, serve para decidir qual chain o usuario deseja que sejam exibidas as regras
function MenuSelecionarTabela {
	#Pedimos qual tabela o usuario deseja trabalhar
	opcao="$($interface --title "Selecionar Tabela" --radiolist "Qual tabela voce deseja trabalhar?" 0 0 0 \
		"T" "Todas" "on" \
		"F" "Filter" "off" \
		"N" "NAT" "off" \
		"M" "Mangle" "off")"

	#Movemos para a proxima funcao e definimos a tabela na variavel Table
	case $opcao in
		T) Table="todas";;
		F) Table="filter"; MenuSelecionarChain;;
		N) Table="nat"; MenuSelecionarChain;;
		M) Table="mangle"; MenuSelecionarChain;;
	esac
}

#Funcao para o menu de listar regras
function MenuListarRegras {
	MenuSelecionarTabela
	ListarRegras
}

#Function para o menu de identificar regras
function MenuIdentificarRegras {
	#Vamos fazer uma pequena estrutura separada por , para o pacote que sera analisado
	#No seguinte formato: <ip_origem>:<mascara_origem>:<ip_destino>:<mascara_destino>:<protocolo>:[porta_origem]:[porta_destino]
	pacote=""

	#Vamos fazer um for para fazer todas as perguntas sequenciais e gerar a variavel do pacote
	for pergunta in "Origem:IP:::fSRCIP" "Origem:Netmask:255.255.255.255:mascara:fSRCNM" "Destino:IP:::fDSTIP" "Destino:Netmask:255.255.255.255:mascara:fDSTNM"; do
		#tipo_end significa se eh origem ou destino
		tipo_end="$(echo $pergunta | cut -d":" -f1)"

		#tipo_info significa se eh IP ou Netmask
		tipo_info="$(echo $pergunta | cut -d":" -f2)"

		#padrao significa se vai ser preenchido um valor padrao no inputbox pro usuario
		padrao="$(echo $pergunta | cut -d":" -f3)"

		#validar significa se devemos ou nao validar como mascara de subrede
		validar="$(echo $pergunta | cut -d":" -f4)"

		#Definimos qual a flag que ira preencher o campo do array
		flag="$(echo $pergunta | cut -d":" -f5)"

		valido=1
		#O usuario deve digitar o IP ate ele ser valido
		while [ $valido -eq 1 ]; do
			valor="$($interface --title "Endereco de $tipo_end" --inputbox "Digite qual o $tipo_info de $tipo_end do pacote" 0 0 "$padrao")"
			ConsistirIP "$valor" "$validar"
			valido=$?

			#Se for uma netmask, vamos traduzir de decimal para notacao CIDR
			if [ "$tipo_info" == "Netmask" ]; then valor="$(TraduzirNetmask "$valor")"; fi
		done

		#Inserindo o valor na flag correspondente do array
		APacote[$flag]="$valor"
	done

	#Pedimos agora para o usuario qual o protocolo da camada de transporte que ele ira usar
	protocolo="$($interface --title "Protocolo" --radiolist "Selecione o protocolo da Camada de Transporte" 0 0 0 \
		"tcp" "TCP" "on" \
		"udp" "UDP" "off" \
		"icmp" "ICMP" "off")"

	APacote[fPROT]="${protocolo}"

	#Se for ICMP ou Qualquer, nao tem porta de origem e destino
	#if [ "$protocolo" = "icmp" ] || [ "$protocolo" = "any" ]; then
	if [ "$protocolo" = "icmp" ]; then
		APacote[fSPORT]="ANY"
		APacote[fDPORT]="ANY"
	else
		#Senao, temos que solicitar a porta de origem e destino
		for pergunta in "origem:fSPORT" "destino:fDPORT"; do
			valido=1
			tipo_info="$(echo $pergunta | cut -d":" -f1)"
			flag="$(echo $pergunta | cut -d":" -f2)"
			#O usuario deve digitar uma porta ate ela ser valida
			while [ $valido -eq 1 ]; do
				valor="$($interface --title "Porta de $tipo_info" --inputbox "Digite qual a porta de $tipo_info do pacote ou 0 para qualquer" 0 0 0)"
				#A porta deve estar entre 0 e 65535 para ser valida
				if [ $valor -ge 0 ] && [ $valor -le 65535 ]; then
					valido=0
					#Se valor estiver como 0, entao consideramos ele como ANY
					if [ $valor -eq 0 ]; then valor="ANY"; fi
					APacote[$flag]="${valor}"
				fi
			done
		done
	fi

	APacote[fINET]="$(GetInterfaceEndereco "${APacote[fSRCIP]}")"
	APacote[fONET]="$(GetInterfaceEndereco "${APacote[fDSTIP]}")"

	#Se nao for possivel definir a interface de saida pelo endereco de origem do pacote, verificamos a tabela de roteamento
	#Infelizmente nao podemos definir a interface de origem devido aos casos de IP Spoofing ou enderecos externos
	if [ -z "${APacote[fONET]}" ]; then APacote[fONET]="$(DefinirInterfaceSaida "${APacote[fDSTIP]}/${APacote[fDSTNM]}")"; fi

	#Definimos qual o caminho de chains builtin iremos percorrer
	caminho=($(DefinirCaminho))
	chainsusuario=($(CarregarChainsUsuario))

	#Se o caminho for INPUT, desconsideramos a interface de saida, se for OUTPUT, desconsideramos a interface de entrada.
	if [ -n "$(echo "${caminho[@]}" | grep "INPUT")" ]; then  APacote[fONET]="";
	elif [ -n "$(echo "${caminho[@]}" | grep "OUTPUT")" ]; then APacote[fINET]="";
	fi

	#Montamos o texto definindo o pacote em uma variavel para simplificar o comando do interface
	texto="O pacote definido foi:\n\nOrigem:${APacote[fSRCIP]}/${APacote[fSRCNM]}\n"
	texto="${texto}Destino:${APacote[fDSTIP]}/${APacote[fDSTNM]}\nProtocolo: ${APacote[fPROT]}\n"
	texto="${texto}Interface de Entrada: ${APacote[fINET]}\nInterface de Saida: ${APacote[fONET]}\n"
	texto="${texto}Porta de Origem: ${APacote[fSPORT]}\nPorta de Destino: ${APacote[fDPORT]}"
	$interface --title "Pacote definido" --msgbox "${texto}" 0 0

	pacote="$(EscreverStringArray "pacote")"

	#Para cada table e chain definida em caminho, vamos percorrer o RuleSet a procura de matches
	qtd_match=0
	parada=0
	caminhopercorrido="Caminho percorrido pelas Chains:\nInicio => "
	for TChain in ${caminho[@]}; do
		Table="$(echo $TChain | cut -d":" -f1)"
		Chain="$(echo $TChain | cut -d":" -f2)"
		BuiltinChain="$Chain"
		paradaChain=0
		nivel=0
		PercorrerRuleset "$Table" "$Chain" 0 $qtd_match
	done
	caminhopercorrido="${caminhopercorrido}Fim"

	$interface --title "caminho percorrido" --msgbox "${caminhopercorrido}" 0 0

	for TChain in ${caminho[@]}; do
		Table="$(echo $TChain | cut -d":" -f1)"
		Chain="$(echo $TChain | cut -d":" -f2)"
		ExibirMatchesTableChain "$Table" "$Chain"
	done
}

#Function para receber nosso usuario, demonstrando uma mensagem de boas vindas e um menu inicial
function MenuPrincipal {
	#Uma tela de boas vindas para nossos usuarios
	$interface --title "Bem vindo!" --msgbox "Seja bem vindo ao IPTables Rule IDentifier (IPTRID)!\nVamos comecar! Escolha o que deseja fazer a seguir" 0 0

	#Tela do menu principal e a opcao do usuario
	opcao="$($interface --title "Menu Principal" --radiolist "O que deseja fazer?" 0 0 0 \
		"I" "Identificar Regra" "on" \
		"L" "Listar Regras" "off")"

	case $opcao in
		L) MenuListarRegras;;
		I) MenuIdentificarRegras;;
	esac
}

#Vamos identificar se temos o Dialog e o grepcidr para trabalhar, senao pedimos para o usuario instalar!
VerificarDependencias

#O programa comeca aqui
MenuPrincipal
