// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// This action is deprecated. Disables ClassicLink DNS support for a VPC. If
// disabled, DNS hostnames resolve to public IP addresses when addressed between a
// linked EC2-Classic instance and instances in the VPC to which it's linked. You
// must specify a VPC ID in the request.
func (c *Client) DisableVpcClassicLinkDnsSupport(ctx context.Context, params *DisableVpcClassicLinkDnsSupportInput, optFns ...func(*Options)) (*DisableVpcClassicLinkDnsSupportOutput, error) {
	if params == nil {
		params = &DisableVpcClassicLinkDnsSupportInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DisableVpcClassicLinkDnsSupport", params, optFns, c.addOperationDisableVpcClassicLinkDnsSupportMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DisableVpcClassicLinkDnsSupportOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DisableVpcClassicLinkDnsSupportInput struct {

	// The ID of the VPC.
	VpcId *string

	noSmithyDocumentSerde
}

type DisableVpcClassicLinkDnsSupportOutput struct {

	// Returns true if the request succeeds; otherwise, it returns an error.
	Return *bool

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDisableVpcClassicLinkDnsSupportMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDisableVpcClassicLinkDnsSupport{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDisableVpcClassicLinkDnsSupport{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDisableVpcClassicLinkDnsSupport(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDisableVpcClassicLinkDnsSupport(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DisableVpcClassicLinkDnsSupport",
	}
}
