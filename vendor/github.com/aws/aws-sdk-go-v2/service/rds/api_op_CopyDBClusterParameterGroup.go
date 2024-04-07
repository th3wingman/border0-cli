// Code generated by smithy-go-codegen DO NOT EDIT.

package rds

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Copies the specified DB cluster parameter group. You can't copy a default DB
// cluster parameter group. Instead, create a new custom DB cluster parameter
// group, which copies the default parameters and values for the specified DB
// cluster parameter group family.
func (c *Client) CopyDBClusterParameterGroup(ctx context.Context, params *CopyDBClusterParameterGroupInput, optFns ...func(*Options)) (*CopyDBClusterParameterGroupOutput, error) {
	if params == nil {
		params = &CopyDBClusterParameterGroupInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CopyDBClusterParameterGroup", params, optFns, c.addOperationCopyDBClusterParameterGroupMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CopyDBClusterParameterGroupOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CopyDBClusterParameterGroupInput struct {

	// The identifier or Amazon Resource Name (ARN) for the source DB cluster
	// parameter group. For information about creating an ARN, see Constructing an ARN
	// for Amazon RDS (https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing)
	// in the Amazon Aurora User Guide. Constraints:
	//   - Must specify a valid DB cluster parameter group.
	//
	// This member is required.
	SourceDBClusterParameterGroupIdentifier *string

	// A description for the copied DB cluster parameter group.
	//
	// This member is required.
	TargetDBClusterParameterGroupDescription *string

	// The identifier for the copied DB cluster parameter group. Constraints:
	//   - Can't be null, empty, or blank
	//   - Must contain from 1 to 255 letters, numbers, or hyphens
	//   - First character must be a letter
	//   - Can't end with a hyphen or contain two consecutive hyphens
	// Example: my-cluster-param-group1
	//
	// This member is required.
	TargetDBClusterParameterGroupIdentifier *string

	// A list of tags. For more information, see Tagging Amazon RDS Resources (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html)
	// in the Amazon RDS User Guide.
	Tags []types.Tag

	noSmithyDocumentSerde
}

type CopyDBClusterParameterGroupOutput struct {

	// Contains the details of an Amazon RDS DB cluster parameter group. This data
	// type is used as a response element in the DescribeDBClusterParameterGroups
	// action.
	DBClusterParameterGroup *types.DBClusterParameterGroup

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCopyDBClusterParameterGroupMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpCopyDBClusterParameterGroup{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpCopyDBClusterParameterGroup{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CopyDBClusterParameterGroup"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpCopyDBClusterParameterGroupValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCopyDBClusterParameterGroup(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opCopyDBClusterParameterGroup(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CopyDBClusterParameterGroup",
	}
}
