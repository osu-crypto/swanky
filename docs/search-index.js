var N=null,E="",T="t",U="u",searchIndex={};
var R=["result","error","twopac","twopac::semihonest","try_from","try_into","borrow","borrow_mut","type_id","typeid","from_cast","into_bits","from_bits","formatter","constant","encode_many","receive_many","Evaluator"];

searchIndex["twopac"]={"doc":"`twopac`: A rust library for secure two-party computation","i":[[4,"Error",R[2],"Errors produced by `twopac`.",N,N],[13,"IoError",E,"An I/O error has occurred.",0,N],[13,"OtError",E,"An oblivious transfer error has occurred.",0,N],[13,"GarblerError",E,"The garbler produced an error.",0,N],[13,"EvaluatorError",E,"The evaluator produced an error.",0,N],[13,"FancyError",E,"Processing the garbled circuit produced an error.",0,N],[0,"semihonest",E,"Implementation of semi-honest two-party computation.",N,N],[3,R[17],R[3],"Semi-honest evaluator.",N,N],[3,"Garbler",E,"Semi-honest garbler.",N,N],[11,"new",E,"Make a new `Evaluator`.",1,[[["c"],["rng"]],[[R[1]],[R[0],[R[1]]]]]],[11,"decode_output",E,"Decode the output post-evaluation.",1,[[["self"]],[["vec",["u16"]],[R[0],["vec",R[1]]],[R[1]]]]],[11,"new",E,"Make a new `Garbler`.",2,[[["c"],["rng"]],[[R[1]],[R[0],[R[1]]]]]],[11,"into",R[2],E,0,[[],[U]]],[11,"to_string",E,E,0,[[["self"]],["string"]]],[11,"from",E,E,0,[[[T]],[T]]],[11,R[4],E,E,0,[[[U]],[R[0]]]],[11,R[5],E,E,0,[[],[R[0]]]],[11,R[6],E,E,0,[[["self"]],[T]]],[11,R[7],E,E,0,[[["self"]],[T]]],[11,R[8],E,E,0,[[["self"]],[R[9]]]],[11,R[10],E,E,0,[[[T]],[T]]],[11,"cast",E,E,0,[[],[U]]],[11,R[11],E,E,0,[[],[U]]],[11,R[12],E,E,0,[[[T]],[T]]],[11,"into",R[3],E,1,[[],[U]]],[11,"from",E,E,1,[[[T]],[T]]],[11,R[4],E,E,1,[[[U]],[R[0]]]],[11,R[5],E,E,1,[[],[R[0]]]],[11,R[6],E,E,1,[[["self"]],[T]]],[11,R[7],E,E,1,[[["self"]],[T]]],[11,R[8],E,E,1,[[["self"]],[R[9]]]],[11,R[10],E,E,1,[[[T]],[T]]],[11,"cast",E,E,1,[[],[U]]],[11,R[11],E,E,1,[[],[U]]],[11,R[12],E,E,1,[[[T]],[T]]],[11,"into",E,E,2,[[],[U]]],[11,"from",E,E,2,[[[T]],[T]]],[11,R[4],E,E,2,[[[U]],[R[0]]]],[11,R[5],E,E,2,[[],[R[0]]]],[11,R[6],E,E,2,[[["self"]],[T]]],[11,R[7],E,E,2,[[["self"]],[T]]],[11,R[8],E,E,2,[[["self"]],[R[9]]]],[11,R[10],E,E,2,[[[T]],[T]]],[11,"cast",E,E,2,[[],[U]]],[11,R[11],E,E,2,[[],[U]]],[11,R[12],E,E,2,[[[T]],[T]]],[11,"from",R[2],E,0,[[[R[1]]],[R[1]]]],[11,"from",E,E,0,[[[R[1]]],[R[1]]]],[11,"from",E,E,0,[[["evaluatorerror"]],[R[1]]]],[11,"from",E,E,0,[[["garblererror"]],[R[1]]]],[11,"from",E,E,0,[[["fancyerror"]],[R[1]]]],[11,"deref",R[3],E,2,[[["self"]]]],[11,"deref_mut",E,E,2,[[["self"]],["gb"]]],[11,"fmt",R[2],E,0,[[["self"],[R[13]]],[R[0]]]],[11,"fmt",E,E,0,[[["self"],[R[13]]],[R[0]]]],[11,R[14],R[3],E,1,[[["self"],["u16"]],[R[0]]]],[11,"add",E,E,1,[[["self"],["wire"]],[R[0]]]],[11,"sub",E,E,1,[[["self"],["wire"]],[R[0]]]],[11,"cmul",E,E,1,[[["self"],["u16"],["wire"]],[R[0]]]],[11,"mul",E,E,1,[[["self"],["wire"]],[R[0]]]],[11,"proj",E,E,1,[[["self"],["vec",["u16"]],["option",["vec"]],["u16"],["wire"]],[R[0]]]],[11,"output",E,E,1,[[["self"],["wire"]],[R[0]]]],[11,R[14],E,E,2,[[["self"],["u16"]],[R[0]]]],[11,"add",E,E,2,[[["self"],["wire"]],[R[0]]]],[11,"sub",E,E,2,[[["self"],["wire"]],[R[0]]]],[11,"cmul",E,E,2,[[["self"],["u16"],["wire"]],[R[0]]]],[11,"mul",E,E,2,[[["self"],["wire"]],[R[0]]]],[11,"proj",E,E,2,[[["self"],["vec",["u16"]],["option",["vec"]],["u16"],["wire"]],[R[0]]]],[11,"output",E,E,2,[[["self"]],[R[0]]]],[11,"receive",E,"Receive a garbler input wire.",1,[[["self"],["u16"]],[[R[1]],[R[0],["wire",R[1]]],["wire"]]]],[11,R[16],E,"Receive garbler input wires.",1,[[["self"]],[["vec",["wire"]],[R[0],["vec",R[1]]],[R[1]]]]],[11,R[15],E,"Perform OT and obtain wires for the evaluator's inputs.",1,[[["self"]],[["vec",["wire"]],[R[0],["vec",R[1]]],[R[1]]]]],[11,"encode",E,E,2,[[["self"],["u16"]],[[R[1]],[R[0],["wire",R[1]]],["wire"]]]],[11,R[15],E,E,2,[[["self"]],[["vec",["wire"]],[R[0],["vec",R[1]]],[R[1]]]]],[11,R[16],E,E,2,[[["self"]],[["vec",["wire"]],[R[0],["vec",R[1]]],[R[1]]]]]],"p":[[4,"Error"],[3,R[17]],[3,"Garbler"]]};
initSearch(searchIndex);addSearchOptions(searchIndex);