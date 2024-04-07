package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/TylerBrock/colorjson"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/http"
	jwt "github.com/golang-jwt/jwt"
	"github.com/jedib0t/go-pretty/table"

	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/term"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage your global Policies",
}

// policysListCmd represents the policy ls command
var policysListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your Policies",
	Run:   policysList,
}

func policysList(cmd *cobra.Command, args []string) {
	client, err := http.NewClient()

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	policiesPath := "policies"
	if perPage != 0 {
		if page == 0 {
			page = 1
		}
		policiesPath += fmt.Sprintf("?page_size=%d", perPage)
		policiesPath += fmt.Sprintf("&page=%d", page)
	} else {
		if page != 0 {
			policiesPath += fmt.Sprintf("?page_size=%d", 100)
			policiesPath += fmt.Sprintf("&page=%d", page)
		}
	}

	if socketID != "" {
		policiesPath += fmt.Sprintf("&org_wide=true&socket_id=%s", socketID)
	}

	policies := []models.Policy{}
	err = client.Request("GET", policiesPath, &policies, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Description", "# Sockets", "Organization Wide"})

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].OrgWide && !policies[j].OrgWide
	})

	for _, s := range policies {
		var socketIDs string

		for _, p := range s.SocketIDs {
			if socketIDs == "" {
				socketIDs = socketIDs + ", " + p
			}

		}
		if s.OrgWide {
			t.AppendRow(table.Row{s.Name, s.Description, "All", "Yes"})
		} else {
			t.AppendRow(table.Row{s.Name, s.Description, len(s.SocketIDs), "No"})
		}
	}
	t.SetStyle(table.StyleLight)
	fmt.Printf("%s\n", t.Render())
}

// policyDeleteCmd represents the policy delete command
var policyDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a policy",
	Run:   policyDelete,
}

// policyDelete represents the policy delete command
func policyDelete(cmd *cobra.Command, args []string) {
	if policyName == "" {
		log.Fatalf("error: invalid policy name")
	}

	policy, err := findPolicyByName(policyName)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	err = client.Request("DELETE", "policy/"+policy.ID, nil, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	fmt.Println("Policy deleted")

}

// policyAttachCmd represents the policy delete command
var policyAttachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attach a policy",
	Run:   policyAttach,
}

func policyAttach(cmd *cobra.Command, args []string) {
	if policyName == "" {
		log.Fatalf("error: invalid policy name")
	}

	if socketID == "" {
		log.Fatalf("error: invalid socket id")
	}

	policy, err := findPolicyByName(policyName)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	body := models.AddSocketToPolicyRequest{
		Actions: []models.PolicyActionUpdateRequest{{
			ID:     socketID,
			Action: "add",
		}},
	}

	err = client.Request("PUT", "policy/"+policy.ID+"/socket", nil, body)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	fmt.Println("Policy attached to socket")
}

// policyDettachCmd represents the policy delete command
var policyDettachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detach a policy",
	Run:   policyDettach,
}

// policyDettach represents the policy dettach command
func policyDettach(cmd *cobra.Command, args []string) {
	if policyName == "" {
		log.Fatalf("error: invalid policy name")
	}

	if socketID == "" {
		log.Fatalf("error: invalid socket id")
	}

	policy, err := findPolicyByName(policyName)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	body := models.AddSocketToPolicyRequest{
		Actions: []models.PolicyActionUpdateRequest{{
			ID:     socketID,
			Action: "remove",
		}},
	}

	err = client.Request("PUT", "policy/"+policy.ID+"/socket", nil, body)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	fmt.Println("Policy detached from socket")
}

// policyShowCmd represents the policy show command
var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a policy",
	Run:   policyShow,
}

// policyShow represents the policy show command
func policyShow(cmd *cobra.Command, args []string) {
	if policyName == "" {
		log.Fatalf("error: invalid policy name")
	}

	policy, err := findPolicyByName(policyName)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Description", "# Sockets", "Organization Wide"})

	if policy.OrgWide {
		t.AppendRow(table.Row{policy.Name, policy.Description, "All", "Yes"})
	} else {
		t.AppendRow(table.Row{policy.Name, policy.Description, len(policy.SocketIDs), "No"})
	}

	t.SetStyle(table.StyleLight)
	fmt.Printf("%s\n", t.Render())

	jsonData, err := json.MarshalIndent(policy.PolicyData, "", "  ")

	if err != nil {
		fmt.Printf("could not marshal json: %s\n", err)
		return
	}
	// This is for the colored JSON output
	var colorData map[string]interface{}
	json.Unmarshal([]byte(jsonData), &colorData)
	f := colorjson.NewFormatter()
	f.Indent = 2
	colorString, _ := f.Marshal(colorData)
	fmt.Printf("\nPolicy Data:\n\n")
	fmt.Println(string(colorString))

}

// policyTestCmd represents the policy test command
var policyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "test a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		var err error

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		currentTime := time.Now().UTC()
		formattedTime := currentTime.Format(time.RFC3339)

		policyTestData := models.PolicyTest{
			Email:     policyTestEmail,
			IPAddress: policyTestIpAddress,
			Time:      formattedTime,
		}

		body := models.PolicyTestRespone{}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("⛔ error: %v", err)
		}
		fmt.Println("Testing Policy:", policy.Name, policy.ID)

		err = client.Request("POST", "policy/"+policy.ID+"/test", &body, policyTestData)
		if err != nil {
			log.Fatalf(fmt.Sprintf("⛔ Error: %v", err))
		}

		if len(body.Info.Failed) > 0 {
			fmt.Println("⛔ Policy Failed")
			// now print the reasons
			fmt.Printf("\n")
			for _, reason := range body.Info.Failed {
				fmt.Println(reason)
			}
		} else {
			fmt.Println("✅ Policy Passed!")
			fmt.Printf("\n")

			// now print the reasons
			for _, reason := range body.Info.Allowed {
				fmt.Println(reason)
			}
			fmt.Println("\nThe following actions would be allowed:")
			// pretty print the actions
			jsonData, err := json.MarshalIndent(body.Actions, "", "  ")
			if err != nil {
				fmt.Printf("could not marshal json: %s\n", err)
				return
			}
			// This is for the colored JSON output
			var colorData map[string]interface{}
			json.Unmarshal([]byte(jsonData), &colorData)
			f := colorjson.NewFormatter()
			f.Indent = 2
			colorString, err := f.Marshal(colorData)
			if err != nil {
				fmt.Printf("could not marshal data: %s\n", err)
				return
			}
			fmt.Println(string(colorString))
		}

	},
}

// policyEditCmd represents the policy edit command
var policyEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		var data []byte
		var err error

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if policyFile != "" {
			data, err = os.ReadFile(policyFile)
			if err != nil {
				fmt.Printf("could not open policy file %s\n", err)
				return
			}

		} else {
			if strings.Contains(runtime.GOOS, "windows") {
				fmt.Printf("not available on windows. Please use the --policy-file or -f option")
				return
			}

			// temporary policy parth and filename
			fpath := path.Join(os.TempDir(), policyName+".json")
			f, err := os.Create(fpath)
			if err != nil {
				fmt.Printf("could not create a policy file %s\n", err)
				return
			}
			f.Close()

			file, err := os.OpenFile(fpath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				fmt.Printf("could not create a policy file %s\n", err)
				return
			}

			bytes, err := json.MarshalIndent(policy.PolicyData, "", "  ")
			if err != nil {
				fmt.Println("Can't serislize", err)
			}

			file.WriteString(string(bytes))
			file.Close()

			c := exec.Command(defaultEnvEditor(), fpath)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			// we defer the removal of temporary prolicy file
			defer os.Remove(fpath)

			if err := (term.TTY{In: os.Stdin, TryDev: true}).Safe(c.Run); err != nil {
				if err, ok := err.(*exec.Error); ok {
					if err.Err == exec.ErrNotFound {
						fmt.Printf("unable to launch the editor")
						return
					}
				}
				fmt.Printf("there was a problem with the editor")
				return
			}
			jsonFile, err := os.Open(fpath)
			if err != nil {
				fmt.Printf("could not open policy file %s\n", err)
				return
			}
			defer jsonFile.Close()
			data, err = io.ReadAll(jsonFile)
			if err != nil {
				fmt.Printf("could not open policy file %s\n", err)
				return
			}
		}

		var policyData models.PolicyData

		err = json.Unmarshal(data, &policyData)
		if err != nil {
			log.Fatalf("⛔ Json format error: %v", err)
		}

		req := models.UpdatePolicyRequest{
			PolicyData: &policyData,
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("⛔ error: %v", err)
		}
		err = client.Request("PUT", "policy/"+policy.ID, nil, req)
		if err != nil {
			log.Fatalf(fmt.Sprintf("⛔ Error: %v", err))
		}

		fmt.Println("✅ Policy Updated")
	},
}

// policyAddCmd represents the policy add command
var policyAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Create a policy",
	Run: func(cmd *cobra.Command, args []string) {

		var data []byte
		var err error

		if policyName == "" {
			log.Fatalf("⛔ error: invalid policy name")
		}

		if policyFile != "" {
			data, err = os.ReadFile(policyFile)
			if err != nil {
				fmt.Printf("⛔ could not open policy file %s\n", err)
				return
			}

		} else {
			if strings.Contains(runtime.GOOS, "windows") {
				fmt.Printf("⛔ not available on windows. Please use the --policy-file or -f option")
				return
			}

			fpath := os.TempDir() + "/" + policyName + ".json"
			f, err := os.Create(fpath)
			if err != nil {
				fmt.Printf("could not create a policy file %s\n", err)
				return
			}
			f.Close()

			file, err := os.OpenFile(fpath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				fmt.Printf("could not create a policy file %s\n", err)
				return
			}

			file.WriteString(policyTemplate())
			file.Close()

			c := exec.Command(defaultEnvEditor(), fpath)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			if err := (term.TTY{In: os.Stdin, TryDev: true}).Safe(c.Run); err != nil {
				if err, ok := err.(*exec.Error); ok {
					if err.Err == exec.ErrNotFound {
						fmt.Printf("⚠️ unable to launch the editor")
						return
					}
				}
				fmt.Printf("⛔ there was a problem with the editor")
				return
			}

			jsonFile, err := os.Open(fpath)
			if err != nil {
				fmt.Printf("⛔ could not open policy file %s\n", err)
				return
			}
			defer jsonFile.Close()

			data, err = io.ReadAll(jsonFile)
			if err != nil {
				fmt.Printf("⚠️ could not open policy file %s\n", err)
				return
			}
		}

		if err != nil {
			fmt.Printf("⚠️ could not open policy file %s\n", err)
			return
		}

		var policyData models.PolicyData

		err = json.Unmarshal(data, &policyData)
		if err != nil {
			log.Fatalf("⛔ Json format error: %v", err)
		}

		req := models.CreatePolicyRequest{
			Name:        policyName,
			PolicyData:  policyData,
			Description: policyDescription,
			Orgwide:     orgwide,
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("⛔ error: %v", err)
		}
		err = client.Request("POST", "policies", nil, req)
		if err != nil {
			log.Fatalf(fmt.Sprintf("⛔ Error: %v", err))
		}

		fmt.Println("✅  Policy created")
	},
}

func defaultEnvEditor() string {
	editor := os.Getenv("EDITOR")

	if len(editor) == 0 {
		editor = "vi"
	}
	if !strings.Contains(editor, " ") {
		return []string{editor}[0]
	}
	if !strings.ContainsAny(editor, "\"'\\") {
		return strings.Split(editor, " ")[0]
	}
	return editor
}

func findPolicyByName(name string) (models.Policy, error) {
	client, err := http.NewClient()

	if err != nil {
		log.Fatalf("⛔ Error: %v", err)
	}

	policiesPath := "policies/find?name=" + name
	policy := models.Policy{}

	err = client.Request("GET", policiesPath, &policy, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("⛔ Error: %v", err))
	}

	return policy, nil
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policysListCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyAttachCmd)
	policyCmd.AddCommand(policyDettachCmd)
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyEditCmd)
	policyCmd.AddCommand(policyTestCmd)

	policysListCmd.Flags().Int64Var(&perPage, "per_page", 100, "The number of results to return per page.")
	policysListCmd.Flags().Int64Var(&page, "page", 0, "The page of results to return.")
	policysListCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")

	policyDeleteCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyDeleteCmd.MarkFlagRequired("name")

	policyShowCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyShowCmd.MarkFlagRequired("name")

	policyAttachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyAttachCmd.MarkFlagRequired("name")
	policyAttachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyAttachCmd.MarkFlagRequired("socket_id")

	policyDettachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyDettachCmd.MarkFlagRequired("name")
	policyDettachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyDettachCmd.MarkFlagRequired("socket_id")

	policyAddCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyAddCmd.MarkFlagRequired("name")
	policyAddCmd.Flags().StringVarP(&policyDescription, "description", "d", "", "Policy Description")
	policyAddCmd.Flags().StringVarP(&policyFile, "policy-file", "f", "", "Policy Definition File")
	policyAddCmd.Flags().BoolVarP(&orgwide, "orgwide", "o", false, "Organization wide polciy")

	policyEditCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyEditCmd.MarkFlagRequired("name")
	policyEditCmd.Flags().StringVarP(&policyFile, "policy-file", "f", "", "Policy Definition File")

	policyTestCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyTestCmd.MarkFlagRequired("name")
	policyTestCmd.Flags().StringVarP(&policyTestEmail, "email", "e", "", "email address to test")
	policyTestCmd.MarkFlagRequired("email")
	policyTestCmd.Flags().StringVarP(&policyTestIpAddress, "ip", "i", "", "IP address to test")
	policyTestCmd.MarkFlagRequired("ip")

}

const defaultPolicyDataTemplate = `{
	"version": "v1",
	"action": [
		"database",
		"ssh",
		"http",
		"tls"
	],
	"condition": {
		"who": {
		"email": [
			"%s"
		],
		"domain": [
			"example.com"
		]
		},
		"where": {
			"allowed_ip": ["0.0.0.0/0", "::/0"],
			"country": [],
			"country_not": []
		},
		"when": {
			"after": "%s",
			"before": null,
			"time_of_day_after": "00:00:00 UTC",
			"time_of_day_before": "23:59:59 UTC"
		}
	}
}`

func policyTemplate() string {
	// Lets create a template for the policy
	// start with getting the admin email
	adminEmail := ""
	admintoken, err := http.GetToken()
	if err != nil {
		log.Fatalf("Error reading token, make sure you're logged in. %v", err)
	}
	token, err := jwt.Parse(admintoken, nil)
	if token == nil {
		log.Fatalf("Error reading token, make sure you're logged in. %v", err)
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	if _email, ok := claims["user_email"].(string); ok {
		adminEmail = _email
	} else {
		// API tokens don't have an email address for now we'll just use this
		adminEmail = "admin@example.com"
	}

	// Also let's get yesterday's date
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	return fmt.Sprintf(defaultPolicyDataTemplate, adminEmail, yesterday)
}
