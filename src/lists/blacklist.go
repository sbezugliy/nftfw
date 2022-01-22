package blacklist

import 'nftables'

nft := &nftables.Conn{}

// Basic boilerplate; create a table & chain.
blacklist := &nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   "ip_filter",
}
blacklist = nft.AddTable(table)

blacklist := nft.AddChain(&nftables.Chain{
	Name:     "filter_chain",
	Table:    blacklist,
	Type:     nftables.ChainTypeFilter,
	Hooknum:  nftables.ChainHookInput,
	Priority: nftables.ChainPriorityFilter,
})

set := &nftables.Set{
	Name:    "whitelist",
	Table:   ,
	KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses
}

// Create the set with a bunch of initial values.
if err := nft.AddSet(set, []nftables.SetElement{
  {Key: net.ParseIP("8.8.8.8")},
}); err != nil {
	// handle error
}

nft.AddRule(&nftables.Rule{
	Table: table,
	Chain: myChain,
	Exprs: []expr.Any{
		// [ payload load 4b @ network header + 16 => reg 1 ]
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		// [ lookup reg 1 set whitelist ]
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		},
		//[ immediate reg 0 drop ]
		&expr.Verdict{
			Kind: expr.VerdictDrop,
		},
	},
})
if err := nft.Flush(); err != nil {
  // handle error
}
