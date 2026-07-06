package agent

import "github.com/nats-io/nats.go"

type OutboundNATSConfig struct {
	URL   string
	Token string
}

type OutboundNATSClient struct {
	conn *nats.Conn
}

func ConnectOutboundNATS(config OutboundNATSConfig) (*OutboundNATSClient, error) {
	options := []nats.Option{}
	if config.Token != "" {
		options = append(options, nats.Token(config.Token))
	}
	conn, err := nats.Connect(config.URL, options...)
	if err != nil {
		return nil, err
	}
	return &OutboundNATSClient{conn: conn}, nil
}

func (c *OutboundNATSClient) Close() {
	if c != nil && c.conn != nil {
		c.conn.Close()
	}
}
