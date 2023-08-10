// Code generated by smithy-go-codegen DO NOT EDIT.

package cloudformation

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Import existing stacks into a new stack sets. Use the stack import operation to
// import up to 10 stacks into a new stack set in the same account as the source
// stack or in a different administrator account and Region, by specifying the
// stack ID of the stack you intend to import.
func (c *Client) ImportStacksToStackSet(ctx context.Context, params *ImportStacksToStackSetInput, optFns ...func(*Options)) (*ImportStacksToStackSetOutput, error) {
	if params == nil {
		params = &ImportStacksToStackSetInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ImportStacksToStackSet", params, optFns, c.addOperationImportStacksToStackSetMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ImportStacksToStackSetOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ImportStacksToStackSetInput struct {

	// The name of the stack set. The name must be unique in the Region where you
	// create your stack set.
	//
	// This member is required.
	StackSetName *string

	// By default, SELF is specified. Use SELF for stack sets with self-managed
	// permissions.
	//   - If you are signed in to the management account, specify SELF .
	//   - For service managed stack sets, specify DELEGATED_ADMIN .
	CallAs types.CallAs

	// A unique, user defined, identifier for the stack set operation.
	OperationId *string

	// The user-specified preferences for how CloudFormation performs a stack set
	// operation. For more information about maximum concurrent accounts and failure
	// tolerance, see Stack set operation options (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-concepts.html#stackset-ops-options)
	// .
	OperationPreferences *types.StackSetOperationPreferences

	// The list of OU ID's to which the stacks being imported has to be mapped as
	// deployment target.
	OrganizationalUnitIds []string

	// The IDs of the stacks you are importing into a stack set. You import up to 10
	// stacks per stack set at a time. Specify either StackIds or StackIdsUrl .
	StackIds []string

	// The Amazon S3 URL which contains list of stack ids to be inputted. Specify
	// either StackIds or StackIdsUrl .
	StackIdsUrl *string

	noSmithyDocumentSerde
}

type ImportStacksToStackSetOutput struct {

	// The unique identifier for the stack set operation.
	OperationId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationImportStacksToStackSetMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsAwsquery_serializeOpImportStacksToStackSet{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpImportStacksToStackSet{}, middleware.After)
	if err != nil {
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
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addIdempotencyToken_opImportStacksToStackSetMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpImportStacksToStackSetValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opImportStacksToStackSet(options.Region), middleware.Before); err != nil {
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
	return nil
}

type idempotencyToken_initializeOpImportStacksToStackSet struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpImportStacksToStackSet) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpImportStacksToStackSet) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*ImportStacksToStackSetInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *ImportStacksToStackSetInput ")
	}

	if input.OperationId == nil {
		t, err := m.tokenProvider.GetIdempotencyToken()
		if err != nil {
			return out, metadata, err
		}
		input.OperationId = &t
	}
	return next.HandleInitialize(ctx, in)
}
func addIdempotencyToken_opImportStacksToStackSetMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpImportStacksToStackSet{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opImportStacksToStackSet(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "cloudformation",
		OperationName: "ImportStacksToStackSet",
	}
}
