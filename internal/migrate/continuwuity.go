package migrate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"exodus/internal/mx"
)

const commandTimeout = 2 * time.Minute

type ContinuwuityAdmin struct {
	client *mautrix.Client
	room   id.RoomID
	bot    string
}

func NewContinuwuityAdmin(ctx context.Context, c *mautrix.Client) (*ContinuwuityAdmin, error) {
	who, err := c.Whoami(ctx)
	if err != nil {
		return nil, fmt.Errorf("destination admin: %w", err)
	}
	server := who.UserID.Homeserver()
	alias := id.RoomAlias("#admins:" + server)
	resp, err := c.ResolveAlias(ctx, alias)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", alias, err)
	}
	return &ContinuwuityAdmin{client: c, room: resp.RoomID, bot: "@conduit:" + server}, nil
}

func (a *ContinuwuityAdmin) ServerName() string { return mx.ServerName(a.bot) }

// EnsureUserAdmin verifies an existing grant before accepting an already-joined reply.
func (a *ContinuwuityAdmin) EnsureUserAdmin(ctx context.Context, user *mautrix.Client, userID string) error {
	_, err := a.Run(ctx, AdminHint(userID))
	if err == nil || !strings.Contains(err.Error(), "User is already joined in the admin room") {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	endpoint := user.BuildURL(mautrix.BaseURLPath{"_continuwuity", "admin", "rooms", "list"})
	req, checkErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if checkErr != nil {
		return errors.Join(err, checkErr)
	}
	req.Header.Set("Authorization", "Bearer "+user.AccessToken)
	resp, checkErr := user.Client.Do(req)
	if checkErr != nil {
		return errors.Join(err, checkErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w; could not verify %s has server admin rights (HTTP %d)", err, userID, resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("%w; admin verification endpoint did not return JSON", err)
	}
	return nil
}

func (a *ContinuwuityAdmin) Run(ctx context.Context, command string) (string, error) {
	sent, err := a.client.SendMessageEvent(ctx, a.room, event.EventMessage,
		&event.MessageEventContent{MsgType: event.MsgText, Body: command},
		mautrix.ReqSendEvent{TransactionID: "exodus." + rand.Text()})
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	for {
		page, err := a.client.Messages(ctx, a.room, "", "", mautrix.DirectionBackward, nil, 50)
		if err != nil {
			return "", err
		}
		for _, ev := range page.Chunk {
			if string(ev.Sender) != a.bot {
				continue
			}
			_ = ev.Content.ParseRaw(ev.Type)
			msg := ev.Content.AsMessage()
			if msg.RelatesTo == nil || msg.RelatesTo.GetReplyTo() != sent.EventID {
				continue
			}
			if strings.Contains(msg.Body, "Command failed with error") {
				return "", fmt.Errorf("admin command %q: %s", firstLine(command), msg.Body)
			}
			return msg.Body, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("admin command %q: no reply: %w", firstLine(command), ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// Appservice is temporary; it can act as any local user and set timestamps.
type Appservice struct {
	Bot    string
	client *mautrix.Client
}

const appserviceID = "exodus"

func RegisterAppservice(ctx context.Context, admin *ContinuwuityAdmin, dest *mautrix.Client) (*Appservice, error) {
	server := admin.ServerName()
	token := rand.Text()
	registration := fmt.Sprintf(`id: %s
url: null
as_token: %s
hs_token: %s
sender_localpart: exodus
rate_limited: false
namespaces:
  users:
    - exclusive: false
      regex: '@.*:%[4]s'
  aliases:
    - exclusive: false
      regex: '#.*:%[4]s'
  rooms: []
`, appserviceID, token, rand.Text(), regexp.QuoteMeta(server))
	if err := admin.registerAppservice(ctx, registration); err != nil {
		return nil, err
	}
	return &Appservice{Bot: "@exodus:" + server, client: mx.WithToken(dest, token)}, nil
}

func (a *Appservice) Unregister(ctx context.Context, admin *ContinuwuityAdmin) error {
	_, err := admin.Run(ctx, "!admin appservices unregister "+appserviceID)
	return err
}

func (a *ContinuwuityAdmin) registerAppservice(ctx context.Context, registration string) error {
	_, err := a.Run(ctx, "!admin appservices register\n```yaml\n"+strings.TrimRight(registration, "\n")+"\n```")
	return err
}

// Login keeps the keys of an existing device.
func (a *Appservice) Login(ctx context.Context, userID, deviceID, displayName string) (string, error) {
	resp, err := a.client.Login(ctx, &mautrix.ReqLogin{
		Type:                     mautrix.AuthTypeAppservice,
		Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: userID},
		DeviceID:                 id.DeviceID(deviceID),
		InitialDeviceDisplayName: displayName,
	})
	if err != nil {
		return "", fmt.Errorf("log in %s on %s: %w", userID, deviceID, err)
	}
	return resp.AccessToken, nil
}

// Register creates a passwordless account; existing accounts are not an error.
func (a *Appservice) Register(ctx context.Context, userID string) error {
	return registerAppserviceUser(ctx, a.client, userID)
}

func registerAppserviceUser(ctx context.Context, c *mautrix.Client, userID string) error {
	_, _, err := c.Register(ctx, &mautrix.ReqRegister[any]{
		Type: mautrix.AuthTypeAppservice, Username: mx.Localpart(userID), InhibitLogin: true,
	})
	if err != nil && !mx.IsCode(err, "M_USER_IN_USE") {
		return fmt.Errorf("register %s: %w", userID, err)
	}
	return nil
}

func registerNewAppserviceUser(ctx context.Context, c *mautrix.Client, userID string) error {
	response, _, err := c.Register(ctx, &mautrix.ReqRegister[any]{
		Type: mautrix.AuthTypeAppservice, Username: mx.Localpart(userID), InhibitLogin: true,
	})
	if err != nil {
		return fmt.Errorf("register %s: %w", userID, err)
	}
	if response == nil || string(response.UserID) != userID {
		return errors.New("appservice registration returned a different user")
	}
	return nil
}

func (a *Appservice) As(userID string) *mautrix.Client { return mx.As(a.client, userID) }
