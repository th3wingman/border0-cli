// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates an EC2 Instance Connect Endpoint. An EC2 Instance Connect Endpoint
// allows you to connect to an instance, without requiring the instance to have a
// public IPv4 address. For more information, see Connect to your instances
// without requiring a public IPv4 address using EC2 Instance Connect Endpoint (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Connect-using-EC2-Instance-Connect-Endpoint.html)
// in the Amazon EC2 User Guide.
func (c *Client) CreateInstanceConnectEndpoint(ctx context.Context, params *CreateInstanceConnectEndpointInput, optFns ...func(*Options)) (*CreateInstanceConnectEndpointOutput, error) {
	if params == nil {
		params = &CreateInstanceConnectEndpointInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateInstanceConnectEndpoint", params, optFns, c.addOperationCreateInstanceConnectEndpointMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateInstanceConnectEndpointOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CreateInstanceConnectEndpointInput struct {

	// The ID of the subnet in which to create the EC2 Instance Connect Endpoint.
	//
	// This member is required.
	SubnetId *string

	// Unique, case-sensitive identifier that you provide to ensure the idempotency of
	// the request.
	ClientToken *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// Indicates whether your client's IP address is preserved as the source. The
	// value is true or false .
	//   - If true , your client's IP address is used when you connect to a resource.
	//   - If false , the elastic network interface IP address is used when you connect
	//   to a resource.
	// Default: true
	PreserveClientIp *bool

	// One or more security groups to associate with the endpoint. If you don't
	// specify a security group, the default security group for your VPC will be
	// associated with the endpoint.
	SecurityGroupIds []string

	// The tags to apply to the EC2 Instance Connect Endpoint during creation.
	TagSpecifications []types.TagSpecification

	noSmithyDocumentSerde
}

type CreateInstanceConnectEndpointOutput struct {

	// Unique, case-sensitive idempotency token provided by the client in the the
	// request.
	ClientToken *string

	// Information about the EC2 Instance Connect Endpoint.
	InstanceConnectEndpoint *types.Ec2InstanceConnectEndpoint

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateInstanceConnectEndpointMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpCreateInstanceConnectEndpoint{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpCreateInstanceConnectEndpoint{}, middleware.After)
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
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addIdempotencyToken_opCreateInstanceConnectEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpCreateInstanceConnectEndpointValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateInstanceConnectEndpoint(options.Region), middleware.Before); err != nil {
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

type idempotencyToken_initializeOpCreateInstanceConnectEndpoint struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpCreateInstanceConnectEndpoint) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpCreateInstanceConnectEndpoint) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*CreateInstanceConnectEndpointInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *CreateInstanceConnectEndpointInput ")
	}

	if input.ClientToken == nil {
		t, err := m.tokenProvider.GetIdempotencyToken()
		if err != nil {
			return out, metadata, err
		}
		input.ClientToken = &t
	}
	return next.HandleInitialize(ctx, in)
}
func addIdempotencyToken_opCreateInstanceConnectEndpointMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpCreateInstanceConnectEndpoint{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opCreateInstanceConnectEndpoint(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "CreateInstanceConnectEndpoint",
	}
}